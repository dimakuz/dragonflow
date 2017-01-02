# Copyright (c) 2016 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from oslo_log import helpers as log_helpers
from oslo_log import log

from dragonflow.controller.common import constants
from dragonflow.controller import df_base_app

LOG = log.getLogger(__name__)

OF_IN_PORT = 0xfff8

# FIXME
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_IPV6 = 0x86dd
ETH_TYPE_MPLS = 0x8847


class SfcApp(df_base_app.DFlowApp):
    @property
    def dp(self):
        return self.get_datapath()

    @property
    def ofproto(self):
        return self.dp.ofproto

    @property
    def parser(self):
        return self.dp.ofproto_parser

    @log_helpers.log_method_call
    def switch_features_handler(self, ev):
        self.initialize()

        self.mpls_driver = MplsDriver(self)
        self.nsh_driver = None

    @log_helpers.log_method_call
    def initialize(self):
        pass

    @log_helpers.log_method_call
    def _get_portchain_driver(self, pc):
        proto = pc.get_proto()
        if proto == pc.PROTO_MPLS:
            return self.mpls_driver
        elif proto == pc.PROTO_NSH:
            return self.nsh_driver
        else:
            raise RuntimeError('Unsupported portchain proto {0}'.format(proto))

    @log_helpers.log_method_call
    def update_portpairgroup(self, ppg):
        pass

    @log_helpers.log_method_call
    def create_portchain(self, pc):
        driver = self._get_portchain_driver(pc)

        driver.install_encap_flows(pc)
        driver.install_decap_flows(pc)

        for ppg_id in pc.get_port_pair_group_ids():
            ppg = self.db_store.portpairgroups.get(ppg_id)

            driver.install_dispatch_to_ppg_flows(pc, ppg)

            for pp_id in ppg.get_port_pair_ids():
                pp = self.db_store.portpairs.get(pp_id)
                lport = self.db_store.get_port(pp.get_egress_port())

                driver.install_sf_egress_flows(pc, ppg, pp, lport)

    @log_helpers.log_method_call
    def delete_portchain(self, pc):
        pass

    @log_helpers.log_method_call
    def update_portchain(self, pc):
        self.delete_portchain(pc)
        self.create_portchain(pc)

    @log_helpers.log_method_call
    def add_local_port(self, lport):
        pass

    @log_helpers.log_method_call
    def add_remote_port(self, lport):
        pass

    @log_helpers.log_method_call
    def remove_local_port(self, lport):
        pass

    @log_helpers.log_method_call
    def remove_remote_port(self, lport):
        pass


class MplsDriver(object):
    def __init__(self, app):
        self.app = app

    @log_helpers.log_method_call
    def install_encap_flows(self, pc):
        for fc_idx, fc_id in enumerate(pc.get_flow_classifier_ids()):
            LOG.error('dimak install encap %s', fc_id)
            # FIXME only install for relevant FCs
            fc = self.app.db_store.flowclassifiers.get(fc_id)
            label = pc.get_mpls_ingress_label(fc_idx, 0)
            match = self.app.parser.OFPMatch(reg6=fc.get_unique_key())

            # FIXME save ip ver in TC
            action_inst = self.app.parser.OFPInstructionActions(
                self.app.ofproto.OFPIT_APPLY_ACTIONS,
                [self.app.parser.OFPActionPushMpls(ETH_TYPE_MPLS),
                 self.app.parser.OFPActionSetField(mpls_label=label)])

            goto_inst = self.app.parser.OFPInstructionGotoTable(
                constants.SFC_MPLS_DISPATCH_TABLE)

            self.app.mod_flow(
                datapath=self.app.dp,
                inst=[action_inst, goto_inst],
                table_id=constants.SFC_ENCAP_TABLE,
                priority=constants.PRIORITY_HIGH,
                match=match,
            )

    @log_helpers.log_method_call
    def install_decap_flows(self, pc):
        for fc_idx, fc_id in enumerate(pc.get_flow_classifier_ids()):
            LOG.error('dimak install decap %s', fc_id)
            # FIXME only install for relevant FCs
            fc = self.app.db_store.flowclassifiers.get(fc_id)
            last_ppg_idx = len(pc.get_port_pair_group_ids()) - 1

            label = pc.get_mpls_egress_label(fc_idx, last_ppg_idx)
            match = self.app.parser.OFPMatch(eth_type=ETH_TYPE_MPLS,
                                             mpls_label=label)

            # FIXME save ip ver in TC
            action_inst = self.app.parser.OFPInstructionActions(
                self.app.ofproto.OFPIT_APPLY_ACTIONS,
                [self.app.parser.OFPActionPopMpls(ETH_TYPE_IPV4),
                 self.app.parser.OFPActionSetField(reg6=fc.get_unique_key())])

            goto_inst = self.app.parser.OFPInstructionGotoTable(
                constants.SFC_END_OF_CHAIN_TABLE)

            self.app.mod_flow(
                datapath=self.app.dp,
                inst=[action_inst, goto_inst],
                table_id=constants.SFC_MPLS_DISPATCH_TABLE,
                priority=constants.PRIORITY_HIGH,
                match=match,
            )

    @log_helpers.log_method_call
    def install_dispatch_to_ppg_flows(self, pc, ppg):
        for fc_idx, fc_id in enumerate(pc.get_flow_classifier_ids()):
            ppg_idx = pc.get_port_pair_group_ids().index(ppg.get_id())
            label = pc.get_mpls_ingress_label(fc_idx, ppg_idx)

            # FIXME output to relevant port
            # FIXME group bucket
            pp = self.app.db_store.portpairs.get(ppg.get_port_pair_ids()[0])
            lport = self.app.db_store.get_port(pp.get_ingress_port())

            self.app.mod_flow(
                datapath=self.app.dp,
                table_id=constants.SFC_MPLS_DISPATCH_TABLE,
                priority=constants.PRIORITY_HIGH,
                match=self.app.parser.OFPMatch(
                    eth_type=ETH_TYPE_MPLS,
                    mpls_label=label,
                ),
                inst=[
                    self.app.parser.OFPInstructionActions(
                        self.app.ofproto.OFPIT_APPLY_ACTIONS,
                        [
                            self.app.parser.OFPActionOutput(
                                lport.get_external_value('ofport'), 0),
                        ],
                    ),
                ],
            )

    @log_helpers.log_method_call
    def install_sf_egress_flows(self, pc, ppg, pp, lport):
        for fc_idx, fc_id in enumerate(pc.get_flow_classifier_ids()):
            ppg_idx = pc.get_port_pair_group_ids().index(ppg.get_id())
            label = pc.get_mpls_ingress_label(fc_idx, ppg_idx)
            match = self.app.parser.OFPMatch(
                in_port=lport.get_external_value('ofport'),
                eth_type=ETH_TYPE_MPLS,
                mpls_label=label,
            )

            next_label = pc.get_mpls_egress_label(fc_idx, ppg_idx)
            action_inst = self.app.parser.OFPInstructionActions(
                self.app.ofproto.OFPIT_APPLY_ACTIONS,
                [self.app.parser.OFPActionSetField(mpls_label=next_label)],
            )

            goto_inst = self.app.parser.OFPInstructionGotoTable(
                constants.SFC_MPLS_DISPATCH_TABLE)

            self.app.mod_flow(
                datapath=self.app.dp,
                inst=[action_inst, goto_inst],
                table_id=constants.INGRESS_CLASSIFICATION_DISPATCH_TABLE,
                priority=constants.PRIORITY_HIGH,
                match=match,
            )
