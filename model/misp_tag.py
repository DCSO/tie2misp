"""
DCSO TIE2MISP Parser
Copyright (c) 2017, DCSO GmbH
"""
from pymisp import PyMISP

class MISPTag:
    def __init__(self, colour, exportable, name):
        if not isinstance(colour, str) and not colour:
            raise ValueError('Colour must be from type String and not null')

        if not isinstance(exportable, bool):
            raise ValueError('Exportable must be from type Bool and not null')

        if not isinstance(name, str) and not name:
            raise ValueError('Colour must be from type String and not null')

        self.__Colour = colour
        self.__Exportable = exportable
        self.__Name = name

    # Getter
    @property
    def colour(self):
        return self.__Colour

    @property
    def exportable(self):
        return self.__Exportable

    @property
    def name(self):
        return self.__Name

    # Setter
    @colour.setter
    def colour(self, value):
        self.__Colour = value

    @exportable.setter
    def exportable(self, value):
        self.__Exportable = value

    @name.setter
    def name(self, value):
        self.__Name = value

    def serialize(self):
        return {'colour': self.colour, 'exportable': self.exportable, 'name': self.name}

    def upload(self, misp, event):

        misp.add_tag(event, misp.new_tag(self.name, self.colour, self.exportable), True)
