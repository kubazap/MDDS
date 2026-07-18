# Re-eksport symboli z config/settings.py.
# Zachowuje kompatybilnosc z instrukcjami "from config import X" w modulach features/.
from config.settings import *  # noqa: F401, F403
