"""Live Sandbox subsystem.

Currently hosts the Live Sandbox Feedback Loop Engine
(``feedback_loop``): a real-time terminal stream analyzer plus a
dynamic command correction loop wired to the Reflection Engine.

Modules are imported lazily by callers to keep the package import
cheap (heavy deps like the PTY bridge are only pulled when the loop
actually runs against a live session).
"""
