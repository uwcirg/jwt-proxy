import os
import importlib.util
import json

# Store loaded policies as (callable, file_path) tuples in load order
_loaded_policies = []
# Store loaded transformers: request transformers and response transformers
_loaded_request_transformers = []
_loaded_response_transformers = []


def load_policies(app):
    """Load all policies from POLICIES_DIR at application startup.
    
    Policies are loaded once and cached for use during request evaluation.
    """
    global _loaded_policies
    _loaded_policies = []
    
    policies_dir = app.config.get("POLICIES_DIR")
    if not policies_dir:
        app.logger.debug("POLICIES_DIR not configured, no policies loaded")
        return
    
    if not os.path.isdir(policies_dir):
        app.logger.warning("POLICIES_DIR '%s' not found or not a directory", policies_dir)
        return

    policy_files = [
        os.path.join(policies_dir, name)
        for name in sorted(os.listdir(policies_dir))
        if name.endswith(".py") and not name.startswith("__")
    ]

    for file_path in policy_files:
        try:
            module = _load_module_from_path(file_path)
        except Exception as e:
            app.logger.exception("Failed to load policy module %s: %s", file_path, e)
            continue

        policy_callable = None
        if hasattr(module, "evaluate") and callable(getattr(module, "evaluate")):
            policy_callable = getattr(module, "evaluate")
        elif hasattr(module, "rule") and callable(getattr(module, "rule")):
            policy_callable = getattr(module, "rule")

        if not policy_callable:
            app.logger.warning("Policy module %s has no callable 'evaluate' or 'rule'", file_path)
            continue

        _loaded_policies.append((policy_callable, file_path))
        app.logger.info("Loaded policy: %s", file_path)
        
        # Check for transformer functions
        if hasattr(module, "transform_request") and callable(getattr(module, "transform_request")):
            _loaded_request_transformers.append((getattr(module, "transform_request"), file_path))
            app.logger.info("Loaded request transformer: %s", file_path)
        
        if hasattr(module, "transform_response") and callable(getattr(module, "transform_response")):
            _loaded_response_transformers.append((getattr(module, "transform_response"), file_path))
            app.logger.info("Loaded response transformer: %s", file_path)

    app.logger.info("Loaded %d policy module(s) from %s", len(_loaded_policies), policies_dir)


def evaluate_policies(req, user_info=None):
    """Evaluate request against pre-loaded policies in filename order.

    Policies are loaded at application startup via load_policies().
    
    A policy module should expose a callable named `evaluate` (preferred) or `rule` with signature:
        evaluate(request, user_info) -> one of:
            - True / "allow"               => allow request
            - False / "deny"               => deny request
            - None / anything else         => no decision, continue
        Optionally, it may return a tuple: (decision, message)

    Returns a tuple: (decision: bool | None, message: str | None)
    decision == True  => allowed
    decision == False => denied
    decision == None  => no policies made a decision
    """
    from flask import current_app
    
    for policy_callable, file_path in _loaded_policies:
        policy_name = os.path.basename(file_path)
        current_app.logger.info(
            "Evaluating policy rule: %s for %s %s",
            policy_name,
            req.method,
            req.path or req.url if hasattr(req, 'url') else 'unknown'
        )
        
        try:
            result = policy_callable(req, user_info)
        except Exception as e:
            current_app.logger.exception("Policy module %s raised exception: %s", file_path, e)
            # Treat exceptions as no-decision; continue to next policy
            continue

        decision = None
        message = None

        if isinstance(result, tuple) and len(result) >= 1:
            decision = result[0]
            message = result[1] if len(result) >= 2 else None
        else:
            decision = result

        if isinstance(decision, str):
            lowered = decision.lower()
            if lowered == "allow":
                decision = True
            elif lowered == "deny":
                decision = False
            else:
                decision = None

        # Log the decision made by this policy
        if decision is True:
            current_app.logger.info(
                "Policy rule %s made decision: ALLOW%s",
                policy_name,
                f" - {message}" if message else ""
            )
            return True, message
        if decision is False:
            current_app.logger.info(
                "Policy rule %s made decision: DENY%s",
                policy_name,
                f" - {message}" if message else ""
            )
            return False, message
        else:
            current_app.logger.debug(
                "Policy rule %s made decision: NO_DECISION (continuing)",
                policy_name
            )

    return None, None


def apply_request_transformers(req, user_info=None):
    """Apply all request transformers to modify the request body.
    
    Transformers should have signature: transform_request(request, request_body, user_info) -> modified_request_body (dict)
    Returns the modified request body, or original if no transformers apply.
    """
    from flask import current_app
    
    if not req.json:
        return None
    
    modified_body = req.json.copy()
    for transformer, file_path in _loaded_request_transformers:
        transformer_name = os.path.basename(file_path)
        current_app.logger.info(
            "Applying request transformer: %s for %s %s",
            transformer_name,
            req.method,
            req.path or req.url if hasattr(req, 'url') else 'unknown'
        )
        
        # Capture the body before transformation for comparison
        body_before = json.dumps(modified_body, sort_keys=True) if modified_body else None
        
        try:
            result = transformer(req, modified_body, user_info)
            if result is not None:
                body_after = json.dumps(result, sort_keys=True) if result else None
                if body_before != body_after:
                    current_app.logger.info(
                        "Request transformer %s modified the request body",
                        transformer_name
                    )
                else:
                    current_app.logger.debug(
                        "Request transformer %s returned result but made no changes",
                        transformer_name
                    )
                modified_body = result
            else:
                current_app.logger.debug(
                    "Request transformer %s returned None (no modification)",
                    transformer_name
                )
        except Exception as e:
            current_app.logger.exception("Request transformer %s raised exception: %s", file_path, e)
            continue
    
    return modified_body


def apply_response_transformers(req, response_body, user_info=None):
    """Apply all response transformers to modify the response body.
    
    Transformers should have signature: transform_response(request, response_body, user_info) -> modified_response_body
    Returns the modified response body, or None if a FHIR resource was filtered out.
    
    Note: Transformers can return:
    - Modified body (dict): use this as the new body
    - None: indicates no modification needed OR FHIR resource was filtered
      - Caller should check if original was FHIR resource to determine if filtered
    """
    from flask import current_app
    
    if not isinstance(response_body, dict):
        return response_body
    
    # Track if we started with a FHIR resource
    is_fhir_resource = response_body.get("resourceType") is not None
    
    modified_body = response_body
    filtered = False
    
    for transformer, file_path in _loaded_response_transformers:
        transformer_name = os.path.basename(file_path)
        current_app.logger.info(
            "Applying response transformer: %s for %s %s",
            transformer_name,
            req.method,
            req.path or req.url if hasattr(req, 'url') else 'unknown'
        )
        
        # Capture the body before transformation for comparison
        body_before = json.dumps(modified_body, sort_keys=True) if modified_body else None
        
        try:
            result = transformer(req, modified_body, user_info)
            if result is not None:
                body_after = json.dumps(result, sort_keys=True) if result else None
                if body_before != body_after:
                    current_app.logger.info(
                        "Response transformer %s modified the response body",
                        transformer_name
                    )
                else:
                    current_app.logger.debug(
                        "Response transformer %s returned result but made no changes",
                        transformer_name
                    )
                # Transformer returned a modified body
                modified_body = result
                filtered = False  # Reset filtered flag if we got a result
            elif is_fhir_resource and isinstance(modified_body, dict) and modified_body.get("resourceType"):
                # Transformer returned None for a FHIR resource - it was filtered
                current_app.logger.info(
                    "Response transformer %s filtered out FHIR resource",
                    transformer_name
                )
                filtered = True
                break  # Stop processing, resource was filtered
            else:
                current_app.logger.debug(
                    "Response transformer %s returned None (no modification)",
                    transformer_name
                )
            # If result is None for non-FHIR, continue with current modified_body
        except Exception as e:
            current_app.logger.exception("Response transformer %s raised exception: %s", file_path, e)
            continue
    
    # If filtered, return None to signal filtering
    if filtered:
        return None
    
    # Return modified body (should never be None at this point, but fallback to original)
    return modified_body if modified_body is not None else response_body


def _load_module_from_path(path):
    """Dynamically load a module from a filesystem path."""
    module_name = f"policy_{os.path.splitext(os.path.basename(path))[0]}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    assert spec and spec.loader  # for mypy/static analyzers
    spec.loader.exec_module(module)  # type: ignore[assignment]
    return module


