"""
RDS Collector
Collects RDS DB instances and proxies that have Security Groups
"""

import logging
from typing import Dict, List, Any, Optional

from .base_collector import BaseCollector

logger = logging.getLogger(__name__)


class RDSCollector(BaseCollector):
    """Collector for RDS resources"""

    def get_resource_type(self) -> str:
        return "RDS"

    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Collect RDS DB instances across regions"""
        results: Dict[str, List[Dict[str, Any]]] = {region: [] for region in regions}

        for region in regions:
            try:
                client = self.authenticator.get_client("rds", region)

                # DB instances
                paginator = client.get_paginator("describe_db_instances")
                instances: List[Dict[str, Any]] = []
                for page in paginator.paginate():
                    instances.extend(page.get("DBInstances", []))

                enriched_instances = []
                for inst in instances:
                    # Only consider instances in a VPC with SGs
                    sg_ids = [sg.get("VpcSecurityGroupId") for sg in inst.get("VpcSecurityGroups", []) if sg.get("VpcSecurityGroupId")]
                    if not sg_ids:
                        continue
                    enriched = self._enrich_db_instance(inst, region, self._extract_account_id(inst))
                    enriched_instances.append(enriched)

                results[region] = self._filter_resources(enriched_instances)
                logger.info(f"Collected {len(results[region])} RDS instances across region {region}")

            except Exception as e:
                logger.error(f"Failed to collect RDS instances from region {region}: {e}")
                results[region] = []

        return results

    def _extract_account_id(self, inst: Dict[str, Any]) -> str:
        # try to parse from ARN if present
        arn = inst.get("DBInstanceArn")
        if arn:
            try:
                return arn.split(":")[4]
            except Exception:
                return ""
        return ""

    def _enrich_db_instance(self, inst: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        enriched = self._enrich_resource_data(inst, region, account_id)
        dbi_id = inst.get("DBInstanceIdentifier")
        arn = inst.get("DBInstanceArn")
        subnet_group = inst.get("DBSubnetGroup", {})
        subnets = [sn.get("SubnetIdentifier") for sn in subnet_group.get("Subnets", []) if sn.get("SubnetIdentifier")]
        vpc_id = subnet_group.get("VpcId")

        enriched.update({
            "DBInstanceIdentifier": dbi_id,
            "Arn": arn,
            "Engine": inst.get("Engine"),
            "EngineVersion": inst.get("EngineVersion"),
            "DBInstanceClass": inst.get("DBInstanceClass"),
            "MultiAZ": inst.get("MultiAZ"),
            "PubliclyAccessible": inst.get("PubliclyAccessible"),
            "VpcId": vpc_id,
            "SubnetIds": subnets,
            "SecurityGroups": [sg.get("VpcSecurityGroupId") for sg in inst.get("VpcSecurityGroups", []) if sg.get("VpcSecurityGroupId")],
        })
        return enriched
