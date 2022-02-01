import json
from unipath import Path
from cloudgenix import API, jd
import settings


def filter_list_of_dict(items, key, value):
    r_list = list()
    if isinstance(value, list):
        for item in items:
            if item[key] in value:
                r_list.append(item)
    else:
        for item in items:
            if item[key] == value:
                r_list.append(item)
    return r_list


class GetStackInfo(object):
    sdk: API

    def __init__(self, auth_token=None, sdk=None):
        """
        Initialize
        :param auth_token: Auth Token from Prisma SD-WAN, if not provided it will prompt user to login via cli.
        :param sdk: sdk that has already been authenticated.
        """
        self.sdk = sdk
        if not sdk:
            self.sdk = API()
            self.login_prisma_sdwan_sdk(auth_token)

        # All Application Definitions
        self.app_defs_all = list()

        # Path Policies
        self.path_policy_sets = list()
        self.path_policy_stacks = list()
        self.path_prefixes_global = list()
        self.path_prefixes_local = list()
        # QOS Policies
        self.qos_policy_sets = list()
        self.qos_policy_stacks = list()
        self.qos_prefixes_global = list()
        self.qos_prefixes_local = list()
        # NAT Policies
        self.nat_policy_sets = list()
        self.nat_policy_stacks = list()
        self.nat_prefixes_global = list()
        self.nat_prefixes_local = list()
        self.nat_pools = list()

        # Global Parameters
        self.dc_groups = list()
        self.circuit_categories = list()
        self.network_context = list()
        self.global_prefixes = list()

        self.update_data()

    def login_prisma_sdwan_sdk(self, auth_token):
        if auth_token:
            self.sdk.interactive.use_token(settings.prisma_sdwan_auth_token)
        else:
            self.sdk.interactive.login()

    def get_all_data(self):
        """
        Do All the Get Requests
        :return:
        """
        self.path_policy_stacks = self.sdk.get.networkpolicysetstacks().cgx_content.get("items", None)
        self.path_policy_sets = self.sdk.get.networkpolicysets().cgx_content.get("items", None)
        self.path_prefixes_global = self.sdk.get.networkpolicyglobalprefixes().cgx_content.get("items", None)
        self.path_prefixes_local = self.sdk.get.tenant_networkpolicylocalprefixes().cgx_content.get("items", None)

        self.qos_policy_stacks = self.sdk.get.prioritypolicysetstacks().cgx_content.get("items", None)
        self.qos_policy_sets = self.sdk.get.prioritypolicysets().cgx_content.get("items", None)
        self.qos_prefixes_global = self.sdk.get.prioritypolicyglobalprefixes().cgx_content.get("items", None)
        self.qos_prefixes_local = self.sdk.get.tenant_prioritypolicylocalprefixes().cgx_content.get("items", None)

        self.nat_policy_stacks = self.sdk.get.natpolicysetstacks().cgx_content.get("items", None)
        self.nat_policy_sets = self.sdk.get.natpolicysets().cgx_content.get("items", None)
        self.nat_prefixes_global = self.sdk.get.natglobalprefixes().cgx_content.get("items", None)
        self.nat_prefixes_local = self.sdk.get.natlocalprefixes().cgx_content.get("items", None)
        self.nat_pools = self.sdk.get.natpolicypools().cgx_content.get("items", None)

        self.circuit_categories = self.sdk.get.waninterfacelabels().cgx_content.get("items", None)
        self.app_defs_all = self.sdk.get.appdefs().cgx_content.get("items", None)
        self.dc_groups = self.sdk.get.servicelabels().cgx_content.get("items", None)
        self.network_context = self.sdk.get.networkcontexts().cgx_content.get("items", None)
        self.global_prefixes = self.sdk.get.globalprefixfilters().cgx_content.get("items", None)

    def update_data(self):
        # Do all the Get Requests
        self.get_all_data()

        # Update Data
        self.path_sets_combined()
        self.path_stacks_combined()
        self.nat_sets_combined()
        self.nat_stacks_combined()
        self.qos_sets_combined()
        self.qos_stacks_combined()

        self.update_app_data()

    # Helper Functions
    def _update_path_circuit(self, paths):
        """
        Update Paths to reflect GUI Names and Circuit Names
        :param paths:
        :return:
        """
        for path in paths:
            if path["label"] == "public-*":
                path["circuit_category"] = "Any Public"
            elif path["label"] == "private-*":
                path["circuit_category"] = "Any Private"
            else:
                crct_ctgr = filter_list_of_dict(self.circuit_categories, "label", path["label"])[0]["name"]
                path["circuit_category"] = crct_ctgr
            if path['path_type'] == "vpn":
                path["overlay"] = "Prisma SD-WAN VPN"
            elif path['path_type'] == "direct":
                path["overlay"] = "Direct"
            elif path['path_type'] == "servicelink":
                path["overlay"] = "Standard VPN"

    # Beginning of Properties/variables
    @property
    def app_defs_custom(self):
        return filter_list_of_dict(self.app_defs_all.copy(), "app_type", "custom")

    @property
    def app_defs_system_or(self):
        return filter_list_of_dict(self.app_defs_all.copy(), "system_app_overridden", True)

    @property
    def path_prefixes_all(self):
        return self.path_prefixes_local + self.path_prefixes_global

    @property
    def nat_prefixes_all(self):
        return self.nat_prefixes_local + self.nat_prefixes_global

    @property
    def qos_prefixes_all(self):
        return self.qos_prefixes_local + self.qos_prefixes_global

    # Combine all the data into the variables.
    def path_sets_combined(self):
        """
        Add in all the Rules into the Path Policy Set
        :return:
        """
        for item in self.path_policy_sets:
            # Path Rules/Policies for a particular set
            path_policies = self.sdk.get.networkpolicyrules(item["id"]).cgx_content.get("items", None)
            for rule in path_policies:
                # Add Source/Destination Prefixes
                rule['source_prefixes'] = filter_list_of_dict(self.path_prefixes_all, 'id', rule['source_prefixes_id'])
                rule['destination_prefixes'] = filter_list_of_dict(self.path_prefixes_all, 'id', rule['destination_prefixes_id'])

                # Add App_def
                rule['app_def'] = filter_list_of_dict(self.app_defs_all, 'id', rule['app_def_ids'])

                # Add Network Context
                rule['network_context'] = None
                nc = filter_list_of_dict(self.network_context, 'id', rule['network_context_id'])
                if nc:
                    rule['network_context'] = nc[0]

                # Add Path Names and Overlay Name
                if rule['paths_allowed']['active_paths']:
                    self._update_path_circuit(rule["paths_allowed"]['active_paths'])
                if rule['paths_allowed']['backup_paths']:
                    self._update_path_circuit(rule["paths_allowed"]['backup_paths'])
                if rule['paths_allowed']['l3_failure_paths']:
                    self._update_path_circuit(rule["paths_allowed"]['l3_failure_paths'])

                # Add DC Group Name for Active
                if rule['service_context'] is not None:
                    rule['service_context']['active_service_label_name'] = None
                    if rule['service_context']['active_service_label_id']:
                        label_name = filter_list_of_dict(
                            self.dc_groups, "id", rule['service_context']['active_service_label_id']
                        )
                        rule['service_context']['active_service_label_name'] = label_name
                    rule['service_context']['backup_service_label_name'] = None
                    # Add DC Group Name for Backup
                    if rule['service_context']['backup_service_label_id']:
                        label_name = filter_list_of_dict(
                            self.dc_groups, "id", rule['service_context']['backup_service_label_id']
                        )
                        rule['service_context']['backup_service_label_name'] = label_name

            item['policyrules'] = path_policies
        return self.path_policy_sets

    def path_stacks_combined(self):
        self._combine_stack_w_set(self.path_policy_stacks, self.path_policy_sets)

    def nat_sets_combined(self):
        """
        add in all the information for each NAT rule.
        :return:
        """
        for item in self.nat_policy_sets:
            item['source_zone_policyrule'] = list()
            item['destination_zone_policyrule'] = list()
            nat_rules = self.sdk.get.natpolicyrules(item['id']).cgx_content.get("items", None)
            if item['source_zone_policyrule_order']:
                for nat_id in item['source_zone_policyrule_order']:
                    item['source_zone_policyrule'] += self._update_nat_rule(nat_rules, nat_id)

            if item['destination_zone_policyrule_order']:
                for nat_id in item['destination_zone_policyrule_order']:
                    item['destination_zone_policyrule'] += self._update_nat_rule(nat_rules, nat_id)

    def nat_stacks_combined(self):
        self._combine_stack_w_set(self.nat_policy_stacks, self.nat_policy_sets)

    def qos_sets_combined(self):
        """
        add in all the information for each NAT rule.
        :return:
        """
        for item in self.qos_policy_sets:
            item['policyrules'] = self.sdk.get.prioritypolicyrules(item['id']).cgx_content.get("items", None)
            for rule in item['policyrules']:
                # Add Source/Destination Prefixes
                rule['source_prefixes'] = filter_list_of_dict(self.qos_prefixes_all, 'id', rule['source_prefixes_id'])
                rule['destination_prefixes'] = filter_list_of_dict(self.qos_prefixes_all, 'id', rule['destination_prefixes_id'])

                # # Add App_def_name
                # rule['app_def_name'] = self.find_app_name(rule['app_def_ids'])

                # Add App_def
                rule['app_def'] = filter_list_of_dict(self.app_defs_all, 'id', rule['app_def_ids'])

                # Add Network Context
                rule['network_context'] = None
                nc = filter_list_of_dict(self.network_context, 'id', rule['network_context_id'])
                if nc:
                    rule['network_context'] = nc[0]

    def qos_stacks_combined(self):
        self._combine_stack_w_set(self.qos_policy_stacks, self.qos_policy_sets)

    def find_app_name(self, app_def_ids):
        app_def_name = list()
        for app_id in app_def_ids or []:
            app_name = filter_list_of_dict(self.app_defs_all, 'id', app_id)[0]['display_name']
            app_def_name.append(app_name)
        return app_def_name

    def _update_nat_rule(self, nat_rules, nat_id):
        rule = filter_list_of_dict(nat_rules, 'id', nat_id)

        # Find Source Prefix and add to dict
        rule[0]['source_prefixes'] = filter_list_of_dict(
            self.nat_prefixes_all, 'id', rule[0]['source_prefixes_id']
        )
        # Find Destination Prefix and add to dict
        rule[0]['destination_prefixes'] = filter_list_of_dict(
                self.nat_prefixes_all, 'id', rule[0]['destination_prefixes_id']
            )
        for action in rule[0]['actions']:
            action['nat_pool'] = filter_list_of_dict(self.nat_pools, 'id', action["nat_pool_id"])
        # jd(rule)
        return rule

    def _combine_stack_w_set(self, policy_stack, policy_sets):
        # Add the Policy sets by name as key to the Stack.
        for stack in policy_stack:
            # Add new key to dict for policy set name
            stack["policyset_dicts"] = list()
            if stack["policyset_ids"]:
                for policy_set_id in stack["policyset_ids"] or []:
                    stack["policyset_dicts"] += filter_list_of_dict(policy_sets, "id", policy_set_id)
            if "defaultrule_policyset_id" in stack and stack['defaultrule_policyset_id']:
                stack['defaultrule_policyset_dicts'] = filter_list_of_dict(policy_sets, "id", stack['defaultrule_policyset_id'])
        # return policy_stack

    # filtering out functions
    def get_policy_set(self, p_id=None, name=None):
        """
        Search Path Policies by Name or ID.
        :param p_id:
        :param name:
        :return:
        """
        if name:
            return filter_list_of_dict(self.path_policy_sets, "name", name)
        if p_id:
            return filter_list_of_dict(self.path_policy_sets, "id", p_id)

    def update_app_data(self):
        for app in self.app_defs_all:
            for tcp_rule in app['tcp_rules'] or []:
                results = filter_list_of_dict(self.global_prefixes, 'id', tcp_rule['server_filters'])
                tcp_rule['server_filters_dicts'] = results
                results = filter_list_of_dict(self.global_prefixes, 'id', tcp_rule['client_filters'])
                tcp_rule['client_filters_dicts'] = results
            for udp_rules in app['udp_rules'] or []:
                results = filter_list_of_dict(self.global_prefixes, 'id', udp_rules['udp_filters'])
                udp_rules['udp_filters_dicts'] = results
            for ip_rule in app['ip_rules'] or []:
                results = filter_list_of_dict(self.global_prefixes, 'id', ip_rule['dest_filters'])
                ip_rule['dest_filters_dicts'] = results
                results = filter_list_of_dict(self.global_prefixes, 'id', ip_rule['src_filters'])
                ip_rule['src_filters_dicts'] = results

    def output_all_data_json(self, out_path=None):
        if out_path is None:
            out_path = Path('')
        out_path = Path(out_path)
        out_path.mkdir(True)
        output_properties = [
            'circuit_categories',
            'path_policy_sets',
            'path_policy_stacks',
            'nat_policy_sets',
            'nat_policy_stacks',
            'qos_policy_sets',
            'qos_policy_stacks',
            'app_defs_custom',
            'global_prefixes'
        ]
        for prop in output_properties:
            out_path.child(prop+'.json').write_file(json.dumps(getattr(self, prop)))


def main():
    sdk = GetStackInfo(settings.prisma_sdwan_auth_token)
    sdk.output_all_data_json('debug_out')



if __name__ == "__main__":
    main()
