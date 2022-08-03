from typing import Optional, Union, Dict, List, Any


LIST2DICT_THRESHOLD = 256


class DynamicDictList:
    """
    A list-like container class that internally uses dicts to store values when the number of values is less than the
    threshold. Keys must be ints.
    """

    __slots__ = ('list_content', 'dict_content', 'max_size')

    def __init__(self,
                 max_size: Optional[int]=None,
                 content: Optional[Union['DynamicDictList',Dict[int,Any],List[Any]]]=None):
        self.list_content = None
        self.dict_content = None
        self.max_size = max_size

        if content:
            self._initialize_content(content)
        else:
            self.dict_content = { }

    def _initialize_content(self, content):

        if isinstance(content, DynamicDictList):
            # make a copy
            self.list_content = list(content.list_content) if content.list_content is not None else None
            self.dict_content = dict(content.dict_content) if content.dict_content is not None else None
            return

        # initializing from a list or a dict
        if len(content) < LIST2DICT_THRESHOLD:
            # use a dict
            if isinstance(content, list):
                self.dict_content = dict(enumerate(content))
            else:
                self.dict_content = dict(content)
        else:
            # use a list
            if isinstance(content, list):
                self.list_content = list(content)
            else:
                self.list_content = [None] * self.max_size
                for k, v in content.items():
                    self.list_content[k] = v

    def real_length(self) -> int:
        if self.dict_content is not None:
            return len(self.dict_content)
        return len(self.list_content)

    def __len__(self):
        return self.max_size

    def __getitem__(self, key: int):
        if self.dict_content is not None:
            return self.dict_content.get(key, None)
        return self.list_content[key]

    def __setitem__(self, key: int, value: Any):
        if self.dict_content is not None:
            self.dict_content[key] = value
            if len(self.dict_content) >= LIST2DICT_THRESHOLD:
                # switch
                self._initialize_content(self.dict_content)
                self.dict_content = None
        else:
            self.list_content[key] = value

    def __iter__(self):
        if self.dict_content is not None:
            for i in range(self.max_size):
                yield self.dict_content.get(i, None)
        else:
            return iter(self.list_content)
