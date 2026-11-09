import os
import sys

if __package__ in (None, ""):
    # executado como script (``python …/omxpatch_agent/__main__.py``): foi assim que o agente antigo se relançava depois de uma
    # atualização; sem isto o novo processo falhava na importação relativa e o agente ficava desligado (sobretudo no Windows)
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from omxpatch_agent.cli import main
else:
    from .cli import main

sys.exit(main())
