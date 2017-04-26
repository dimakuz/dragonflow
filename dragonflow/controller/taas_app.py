# Copyright (c) 2017 OpenStack Foundation.
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
from oslo_log import helpers
from oslo_log import log

from dragonflow.controller import df_base_app
from dragonflow.db.models import taas
from dragonflow.db.models import constants


LOG = log.getLogger(__name__)


class TapAsAServiceApp(df_base_app.DFlowApp):
    @helpers.log_method_call
    def switch_features_handler(self, ev):
        self._added_ports = set()

    @df_base_app.register_event(taas.TapService, constants.EVENT_CREATED)
    @helpers.log_method_call
    def _tap_service_created(self, tap_service):
        pass

    @df_base_app.register_event(taas.TapService, constants.EVENT_DELETED)
    @helpers.log_method_call
    def _tap_service_deleted(self, tap_service):
        pass

    @df_base_app.register_event(taas.TapFlow, constants.EVENT_CREATED)
    @helpers.log_method_call
    def _tap_flow_created(self, tap_flow):
        if tap_flow.source_port in self._added_ports:
            self._add_tap_flow(tap_flow)

    @df_base_app.register_event(taas.TapFlow, constants.EVENT_DELETED)
    @helpers.log_method_call
    def _tap_flow_deleted(self, tap_flow):
        if tap_flow.source_port in self._added_ports:
            self._remove_tap_flow(tap_flow)

    @helpers.log_method_call
    def add_local_port(self, lport):
        self._added_ports.add(lport.id)
        tap_flow = self.db_store2.get_one(
            taas.TapFlow(source_port=lport.id),
            index=taas.TapFlow.get_index('source_port'),
        )
        if tap_flow:
            self._add_tap_flow(tap_flow)

    @helpers.log_method_call
    def remove_local_port(self, lport):
        self._added_ports.remove(lport.id)
        tap_flow = self.db_store2.get_one(
            taas.TapFlow(source_port=lport.id),
            index=taas.TapFlow.get_index('source_port'),
        )
        if tap_flow:
            self._remove_tap_flow(tap_flow)

    def _add_tap_flow(self, tap_flow):
        pass

    def _remove_tap_flow(self, tap_flow):
        pass
