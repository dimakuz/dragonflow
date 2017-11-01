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

from jsonmodels import fields
import uuid

from oslo_serialization import jsonutils

from dragonflow.common import utils as df_utils
from dragonflow.db import api_nb
from dragonflow.db import model_framework as mf
from dragonflow.db.models import all  # noqa


DF_SKYDIVE_NAMESPACE_UUID = uuid.UUID('8a527b24-f0f5-4c1f-8f3d-6de400aa0145')


def output_edge(edges, nb_api, instance, field_name):
    field_proxy = getattr(instance, field_name)
    field = nb_api.get(field_proxy)
    id_str = '{}->{}'.format(instance.id, field.id)
    metadata = {
        'source': 'dragonflow',
        'source_type': type(instance).__name__,
        'dest_type': type(field).__name__,
    }
    result = {
        'ID': str(uuid.uuid5(DF_SKYDIVE_NAMESPACE_UUID, id_str)),
        'Child': "DF-{}".format(instance.id),
        'Parent': "DF-{}".format(field.id),
        'Host': 'dragonflow',
        'Metadata': metadata
    }
    edges.append(result)

def output_table_node_edges(edges, nb_api, instance):
    for key, field in type(instance).iterate_over_fields():
        if isinstance(field, fields.ListField):
            types = field.items_types
            continue  # TODO(oanson) Not supported
        else:
            types = field.types
        for field_type in types:
            try:
                model = field_type.get_proxied_model()
                output_edge(edges, nb_api, instance, key)
            except AttributeError:
                pass  # ignore
            break

def output_table_node(nodes, edges, nb_api, instance):
    metadata = {
        'ID': "DF-{}".format(instance.id),
        'Type': type(instance).__name__,
        'source': 'dragonflow',
        'data': instance.to_struct(),
        'Name': getattr(instance, 'name', None) or instance.id
    }
    result = {
        'Metadata': metadata,
        'ID': "DF-{}".format(instance.id),
        'Host': 'dragonflow'}
    nodes.append(result)
    output_table_node_edges(edges, nb_api, instance)

def output_table(nodes, edges, nb_api, table_name):
    model = mf.get_model(table_name)
    instances = nb_api.get_all(model)
    for instance in instances:
        output_table_node(nodes, edges, nb_api, instance)

def output_tables():
    nb_api = api_nb.NbApi.get_instance(False)
    nodes = []
    edges = []
    for table_name in mf.iter_tables():
        output_table(nodes, edges, nb_api, table_name)
    result = {
        'Nodes': nodes,
        'Edges': edges,
    }
    return result

def main():
    df_utils.config_parse()
    result = output_tables()
    with open('output.json', 'w') as f:
        jsonutils.dump(result, f)
    print('Done!')
    #nodes = []
    #nb_api = api_nb.NbApi.get_instance(False)
    #output_table(nodes.append, nb_api, 'LogicalPort')
    #output_table(nodes.append, nb_api, 'LogicalSwitch')
    #edges = []
    #output_edges(edges.append, nb_api, 'LogicalPort', 'lswitch')
    #result = {
    #    'Nodes': nodes,
    #    'Edges': edges,
    #}
    #with open('output.json', 'w') as f:
    #    jsonutils.dump(result, f)
    #print('Done!')

if __name__ == "__main__":
    main()


# [stack@oanson-x4 skydive (master)]$ export GO_BINDATA_FLAGS=-debug
