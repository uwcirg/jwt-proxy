import os
import importlib.util

# Store loaded policies as (callable, file_path) tuples in load order
_loaded_policies = []


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
    for policy_callable, file_path in _loaded_policies:
        try:
            result = policy_callable(req, user_info)
        except Exception as e:
            from flask import current_app
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

        if decision is True:
            return True, message
        if decision is False:
            return False, message

    return None, None


def _load_module_from_path(path):
    """Dynamically load a module from a filesystem path."""
    module_name = f"policy_{os.path.splitext(os.path.basename(path))[0]}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    assert spec and spec.loader  # for mypy/static analyzers
    spec.loader.exec_module(module)  # type: ignore[assignment]
    return module


