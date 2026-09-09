import base64
import json
import logging
import sys
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("auth_scope_authorizer")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(logging.Formatter("[%(levelname)s] %(asctime)s - %(message)s"))
logger.handlers = [stream_handler]

class TokenInspectionEngine:
    def __init__(self, required_permissions: List[str]):
        self.required_permissions = required_permissions

    def decode_token_payload(self, raw_token: str) -> Dict[str, Any]:
        parts = raw_token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed JWT structure: token must contain 3 segments")
        
        payload_segment = parts[1]
        missing_padding = len(payload_segment) % 4
        if missing_padding:
            payload_segment += "=" * (4 - missing_padding)
            
        decoded_bytes = base64.urlsafe_b64decode(payload_segment)
        return json.loads(decoded_bytes.decode("utf-8"))

    def validate_scopes(self, token_claims: Dict[str, Any]) -> bool:
        logger.info(f"Evaluating claims for subject: {token_claims.get('sub')}")
        
        # Claims can have scopes formatted as a space-separated string (RFC 6749 standard)
        # e.g., "orders:read orders:write reports:export"
        scopes = token_claims.get("scope", "")
        
        resolved_actions = []
        # FAILS HERE: The code treats 'scopes' as an iterable list of dict permission objects
        # Iterating over string yields individual characters, or calling .get() on elements fails
        for scope_entry in scopes:
            # scope_entry is a 1-character string: AttributeError: 'str' object has no attribute 'get'
            action_name = scope_entry.get("action")
            resolved_actions.append(action_name)

        return all(perm in resolved_actions for perm in self.required_permissions)

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("Starting Lambda custom authorizer evaluation...")

    # Realistic JWT token with standard space-delimited OAuth2 scopes
    header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    # payload contains {"sub": "usr_9910", "scope": "orders:read orders:write", "exp": 1780000000}
    payload_b64 = "eyJzdWIiOiAidXNyXzk5MTAiLCAic2NvcGUiOiAib3JkZXJzOnJlYWQgb3JkZXJzOndyaXRlIiwgImV4cCI6IDE3ODAwMDAwMDB9"
    signature_b64 = "4Pz8_fake_signature_hash_data_abc123"
    simulated_jwt = f"{header_b64}.{payload_b64}.{signature_b64}"

    simulated_event = {
        "type": "TOKEN",
        "authorizationToken": f"Bearer {simulated_jwt}",
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:api-id/prod/GET/orders"
    }

    raw_header = simulated_event.get("authorizationToken", "")
    token = raw_header.replace("Bearer ", "").strip()

    engine = TokenInspectionEngine(required_permissions=["orders:read"])
    claims = engine.decode_token_payload(token)
    
    is_authorized = engine.validate_scopes(claims)
    logger.info(f"Authorization verdict: {is_authorized}")

    return {
        "principalId": claims.get("sub"),
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow" if is_authorized else "Deny",
                    "Resource": simulated_event["methodArn"]
                }
            ]
        }
    }

if __name__ == "__main__":
    lambda_handler({}, None)
