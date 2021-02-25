from cloudshell.snmp.quali_snmp import QualiSnmp, QualiMibTable
import cloudshell.devices.standards.networking.autoload_structure as networking_model
from cloudshell.shell.core.driver_context import AutoLoadDetails
from cloudshell.devices.autoload.autoload_builder import AutoloadDetailsBuilder
import re


class ZTEGenericSNMPDiscovery:

    def __init__(self, snmp_params, shell_name, shell_type, resource_name, logger):
        self.logger = logger

        self.snmp = QualiSnmp(snmp_parameters=snmp_params,
                              logger=logger)

        self.resource_name = resource_name
        self.shell_name = shell_name
        self.shell_type = shell_type
        self.resource_model = networking_model

        self.resource = self.resource_model.GenericResource(shell_name=shell_name,
                                                            shell_type=shell_type,
                                                            name=resource_name,
                                                            unique_id=resource_name)

        self._chassis = {}
        self.entity_table_black_list = []
        self.chassis_list = []
        self.module_dict = dict()
        self.module_num = 1
        self.port_exclude_pattern = 'TEST'
        self.port_mapping = {}
        self.port_list = []
        self.power_supply_list = []

    def discover(self):
        """
        :param str ip: The device IP address
        :param str model: The device model in CloudShell
        :param str vendor: The device vendor
        :param SNMPV2ReadParameters snmp_params: The device vendor
        :return: The loaded resources and attributes
        :rtype: AutoLoadDetails
        """

        self._get_device_details()
        self._load_snmp_tables()

        self._build_chassis()
        self._build_ports()

        autoload_details = AutoloadDetailsBuilder(self.resource).autoload_details()
        self._log_autoload_details(autoload_details)
        return autoload_details

    def _get_device_details(self):
        """Get root element attributes
        """
        self.logger.info("Building Root")

        sysDescr = self.snmp.get_property('SNMPv2-MIB', 'sysDescr', '0')

        version_match = sysDescr.split('Version: ')[-1]
        version = version_match.split(' ')[0]

        model_match = sysDescr.split(',')[0]
        model = model_match.split(' ')[-1]

        vendor = 'ZTE'

        #match_version = re.search(r'Version:\s+(?P<software_version>\S+)\S*\s+', sysDescr)
        #print sysDescr
        #if match_version:
        #    match_version = match_version.groupdict()['software_version'].replace(',', '')

        #match_vendor_model = re.search(r'HwSku:\s+(?P<vendor_model>\S+)\S*\s+', sysDescr)
        #if match_vendor_model:
        #    match_vendor_model = match_vendor_model.groupdict()['vendor_model'].replace(',', '')
        #    vendor, model = match_vendor_model.split('-', 1)
        #else:
        #    vendor = model = None

        self.resource.contact_name = self.snmp.get_property('SNMPv2-MIB', 'sysContact', '0')
        self.resource.system_name = self.snmp.get_property('SNMPv2-MIB', 'sysName', '0')
        self.resource.location = self.snmp.get_property('SNMPv2-MIB', 'sysLocation', '0')
        self.resource.os_version = version
        self.resource.vendor = vendor
        self.resource.model = model

    def _log_autoload_details(self, autoload_details):
        """
        Logging autoload details
        :param autoload_details:
        :return:
        """
        self.logger.info('-------------------- <RESOURCES> ----------------------')
        for resource in autoload_details.resources:
            self.logger.info(
                '{0:15}, {1:20}, {2}'.format(resource.relative_address, resource.name, resource.unique_identifier))
        self.logger.info('-------------------- </RESOURCES> ----------------------')

        self.logger.info('-------------------- <ATTRIBUTES> ---------------------')
        for attribute in autoload_details.attributes:
            self.logger.info('-- {0:15}, {1:60}, {2}'.format(attribute.relative_address, attribute.attribute_name,
                                                              attribute.attribute_value))
        self.logger.info('-------------------- </ATTRIBUTES> ---------------------')

    def _load_snmp_tables(self):
        """ Load all  required snmp tables
        :return:
        """

        self.if_table = self.snmp.get_table('IF-MIB', 'ifDescr')
        self.entity_table = self._get_entity_table()
        #if len(self.entity_table.keys()) < 1:
            #raise Exception('Cannot load entPhysicalTable. Autoload cannot continue')

        self.lldp_local_table = self.snmp.get_table('LLDP-MIB', 'lldpLocPortDesc')
        self.lldp_remote_table = self.snmp.get_table('LLDP-MIB', 'lldpRemTable')
        self.duplex_table = self.snmp.get_table('EtherLike-MIB', 'dot3StatsIndex')
        self.ip_v4_table = self.snmp.get_table('IP-MIB', 'ipAddrTable')

    def _get_entity_table(self):
        """Read Entity-MIB and filter out device's structure and all it's elements, like ports, modules, chassis, etc.
        :rtype: QualiMibTable
        :return: structured and filtered EntityPhysical table.
        """

        result_dict = QualiMibTable('entPhysicalTable')

        entity_table_critical_port_attr = {'entPhysicalContainedIn': 'str',
                                           'entPhysicalVendorType': 'str'}
        entity_table_optional_port_attr = {'entPhysicalDescr': 'str', 'entPhysicalSerialNum': 'str'}

        physical_indexes = self.snmp.get_table('ENTITY-MIB', 'entPhysicalClass')
        for index in physical_indexes.keys():
            is_excluded = False
            #if physical_indexes[index]['entPhysicalParentRelPos'] == '':
            #    self.exclusion_list.append(index)
            #    continue
            temp_entity_table = physical_indexes[index].copy()
            #temp_entity_table.update(self.snmp.get_properties('ENTITY-MIB', index, entity_table_critical_port_attr)
            #                         [index])
            #if temp_entity_table['entPhysicalContainedIn'] == '':
            #    is_excluded = True
            #    self.exclusion_list.append(index)

            for item in self.entity_table_black_list:
                if item in temp_entity_table['entPhysicalVendorType'].lower():
                    is_excluded = True
                    break

            if is_excluded is True:
                continue

            temp_entity_table.update(self.snmp.get_properties('ENTITY-MIB', index, entity_table_optional_port_attr)
                                     [index])

            '''if temp_entity_table['entPhysicalClass'] == '':
                vendor_type = self.snmp.get_property('ENTITY-MIB', 'entPhysicalVendorType', index)
                index_entity_class = None
                if vendor_type == '':
                   continue
                if 'cevcontainer' in vendor_type.lower():
                    index_entity_class = 'container'
                elif 'cevchassis' in vendor_type.lower():
                    index_entity_class = 'chassis'
                elif 'cevmodule' in vendor_type.lower():
                    index_entity_class = 'module'
                elif 'cevport' in vendor_type.lower():
                    index_entity_class = 'port'
                elif 'cevpowersupply' in vendor_type.lower():
                    index_entity_class = 'powerSupply'
                if index_entity_class:
                    temp_entity_table['entPhysicalClass'] = index_entity_class
            else:'''
            temp_entity_table['entPhysicalClass'] = temp_entity_table['entPhysicalClass'].replace("'", "")

            if re.search(r'stack|chassis|module|port|powerSupply|container|backplane',
                         temp_entity_table['entPhysicalClass']):
                result_dict[index] = temp_entity_table

            if temp_entity_table['entPhysicalClass'] == 'chassis':
                self.chassis_list.append(index)
                break
            #elif temp_entity_table['entPhysicalClass'] == 'port':
            #    if not re.search(self.port_exclude_pattern, temp_entity_table['entPhysicalName'], re.IGNORECASE) \
            #            and not re.search(self.port_exclude_pattern, temp_entity_table['entPhysicalDescr'],
            #                              re.IGNORECASE):
            #        port_id = self._get_mapping(index, temp_entity_table['entPhysicalDescr'])
            #        if port_id and port_id in self.if_table and port_id not in self.port_mapping.values():
            #            self.port_mapping[index] = port_id
            #            self.port_list.append(index)
            #elif temp_entity_table['entPhysicalClass'] == 'powerSupply':
            #    self.power_supply_list.append(index)

        #self._filter_entity_table(result_dict)
        return result_dict

    def _get_mapping(self, port_index, port_descr):
        """Get mapping from entPhysicalTable to ifTable.
        Build mapping based on ent_alias_mapping_table if exists else build manually based on
        entPhysicalDescr <-> ifDescr mapping.
        :return: simple mapping from entPhysicalTable index to ifTable index:
        |        {entPhysicalTable index: ifTable index, ...}
        """

        port_id = None
        try:
            ent_alias_mapping_identifier = self.snmp.get(('ENTITY-MIB', 'entAliasMappingIdentifier', port_index, 0))
            port_id = int(ent_alias_mapping_identifier['entAliasMappingIdentifier'].split('.')[-1])
        except Exception as e:

            if_table_re = "/".join(re.findall('\d+', port_descr))
            for interface in self.if_table.values():
                if re.search(if_table_re, interface['ifDescr']):
                    port_id = int(interface['suffix'])
                    break
        return port_id

    def _build_chassis(self):
        """
        Build Chassis resources and attributes
        :return:
        """
        self.logger.debug('Building Chassis')
        for index in self.chassis_list:
            chassis = self.resource_model.GenericChassis(shell_name=self.shell_name,
                                                         name="Chassis {}".format(index),
                                                         unique_id="{0}.{1}.{2}".format(self.resource_name, "chassis", index))
            chassis.serial_number = self.snmp.get_property('ENTITY-MIB', 'entPhysicalSerialNum', index)

            self.resource.add_sub_resource(index, chassis)

            self._chassis[index] = chassis

        if self.chassis_list == []:
            chassis = self.resource_model.GenericChassis(shell_name=self.shell_name,
                                                         name="Chassis {}".format(1),
                                                         unique_id="{0}.{1}.{2}".format(self.resource_name, "chassis", '1'))
            self.resource.add_sub_resource('1', chassis)
            self.chassis_list.append('1')
            self._chassis['1'] = chassis

    def _build_ports(self):
        if self.chassis_list == {}:
            chassis = self._chassis['1']
        else:
            chassis = self._chassis[self.chassis_list[0]]

        interface_indexes = self.snmp.get_table('IF-MIB', 'ifDescr')

        for index in interface_indexes.keys():
            #interface_name = self.snmp.get_property('IF-MIB', 'ifDescr', index).replace('/', '-').replace(':', '-')
            interface_name = self.snmp.get_property('IF-MIB', 'ifName', index).replace('/', '-').replace(':', '-')

            if interface_name != '' and 'Channel' not in interface_indexes.get(index).get('ifDescr'):
                interface = self.resource_model.GenericPort(shell_name=self.shell_name,
                                                            name=interface_name,
                                                            unique_id="{0}.{1}.{2}".format(self.resource_name, "port",
                                                                                           index))
                interface.l2_protocol_type = self.snmp.get_property('IF-MIB', 'ifType', index).strip('\'')
                interface.mac_address = self.snmp.get_property('IF-MIB', 'ifPhysAddress', index)
                interface.mtu = self.snmp.get_property('IF-MIB', 'ifMtu', index)
                interface.bandwidth = self.snmp.get_property('IF-MIB', 'ifHighSpeed', index)

                duplex = None
                snmp_result = self.snmp.get_property('EtherLike-MIB', 'dot3StatsDuplexStatus', index)
                if snmp_result:
                    port_duplex = snmp_result.strip('\'')
                    if re.search(r'[Ff]ull', port_duplex):
                        duplex = 'Full'
                    else:
                        duplex = 'Half'
                interface.duplex = duplex

                interface.adjacent = None
                interface.auto_negotiation = False
                interface.port_description = interface_indexes.get(index).get('ifDescr')

                module = self._get_module(interface_name)

                if module is not None:
                    module.add_sub_resource(index, interface)


    def _get_module(self, interface_name):
        module = None
        if self.chassis_list == {}:
            chassis = self._chassis['1']
        else:
            chassis = self._chassis[self.chassis_list[0]]

        if interface_name.count('-') >= 3:
            temp = interface_name.split('-')
            key = '-'.join(temp[0:len(temp) - 1])

            if key not in self.module_dict:
                module = self.resource_model.GenericModule(shell_name=self.shell_name,
                                                           name="Module {}".format(self.module_num),
                                                           unique_id="{0}.{1}.{2}".format(self.resource_name, "module", self.module_num))
                chassis.add_sub_resource(self.module_num, module)
                self.module_dict[key] = module
                self.module_num += 1
            else:
                module = self.module_dict[key]
        else:
            if 'default' not in self.module_dict:
                module = self.resource_model.GenericModule(shell_name=self.shell_name,
                                                           name="Module {}".format(self.module_num),
                                                           unique_id="{0}.{1}.{2}".format(self.resource_name, "module", self.module_num))
                chassis.add_sub_resource(self.module_num, module)
                self.module_dict['default'] = module
                self.module_num += 1
            else:
                module = self.module_dict['default']

        return module