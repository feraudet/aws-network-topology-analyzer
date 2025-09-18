"""
ELB Collector (ALB/NLB via ELBv2)
Collects Application and Network Load Balancers that have Security Groups
"""

import logging
from typing import Dict, List, Any, Optional

from .base_collector import BaseCollector

logger = logging.getLogger(__name__)


class ELBCollector(BaseCollector):
    """Collector for ELBv2 load balancers (ALB/NLB)"""

    def get_resource_type(self) -> str:
        return "ELBv2"

    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Collect ELBv2 load balancers across regions"""
        results: Dict[str, List[Dict[str, Any]]] = {region: [] for region in regions}

        for region in regions:
            try:
                client = self.authenticator.get_client("elbv2", region)

                paginator = client.get_paginator("describe_load_balancers")
                lbs: List[Dict[str, Any]] = []
                for page in paginator.paginate():
                    lbs.extend(page.get("LoadBalancers", []))

                enriched_lbs = []
                for lb in lbs:
                    # Only ALBs have SGs; NLBs may not. But we still include if SGs present.
                    sgs = lb.get("SecurityGroups", [])
                    if not sgs:
                        # Keep NLBs in inventory to map routing, but they may not have SGs. Include anyway for completeness.
                        pass
                    account_id = self._extract_account_id(lb)
                    enriched = self._enrich_lb(lb, region, account_id)
                    enriched_lbs.append(enriched)

                results[region] = self._filter_resources(enriched_lbs)
                logger.info(f"Collected {len(results[region])} Load Balancers across region {region}")

            except Exception as e:
                logger.error(f"Failed to collect Load Balancers from region {region}: {e}")
                results[region] = []

        return results

    def _extract_account_id(self, lb: Dict[str, Any]) -> str:
        arn = lb.get("LoadBalancerArn") or lb.get("Arn")
        if arn:
            try:
                return arn.split(":")[4]
            except Exception:
                return ""
        return ""

    def _enrich_lb(self, lb: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        enriched = self._enrich_resource_data(lb, region, account_id)
        # Normalize fields and add convenience keys
        azs = lb.get("AvailabilityZones", [])
        subnet_ids = []
        if isinstance(azs, list):
            for az in azs:
                if isinstance(az, dict) and az.get("SubnetId"):
                    subnet_ids.append(az["SubnetId"])

        arn = lb.get("LoadBalancerArn") or lb.get("Arn")
        enriched.update({
            "Arn": arn,
            "LoadBalancerArn": arn,
            "LoadBalancerName": lb.get("LoadBalancerName"),
            "Type": lb.get("Type"),
            "Scheme": lb.get("Scheme"),
            "VpcId": lb.get("VpcId"),
            "SecurityGroups": lb.get("SecurityGroups", []),
            "SubnetIds": subnet_ids,
            "DNSName": lb.get("DNSName"),
            "State": lb.get("State"),
        })
        return enriched
