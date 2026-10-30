from .core import CORE_MODULES
from .advanced import ADVANCED_MODULES

ALL_MODULES = {module.id: module for module in [*CORE_MODULES, *ADVANCED_MODULES]}

