"""vmctl-core — shared foundation for VM conservation controllers.

Holds the pieces both the research workbench and the (future) exhibition runtime
depend on: the pluggable VM backend abstraction, the shared plugin spec/runtime,
snapshot helpers, screen capture, and guest I/O.

Dependency rule: this package never imports from research or exhibition apps.
Apps depend on core; core depends on nothing app-specific.
"""

__version__ = "0.1.0"
