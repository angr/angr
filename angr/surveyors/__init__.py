from .explorer import Explorer
from .executor import Executor
from .escaper import Escaper
from .slicecutor import Slicecutor, HappyGraph

all_surveyors = { 'Explorer': Explorer, 'Executor': Executor, 'Escaper': Escaper, 'Slicecutor': Slicecutor }
