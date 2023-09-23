"""
Module to detect common functions used in c/c++ applications
"""
from chenpy.detectors.common import get_method_callIn


async def get_gets(connection):
    """Retrive all usages of gets function"""
    return await get_method_callIn(connection, "gets")


async def get_getwd(connection):
    """Retrive all usages of getwd function"""
    return await get_method_callIn(connection, "getwd")


async def get_scanf(connection):
    """Retrive all usages of scanf function"""
    return await get_method_callIn(connection, "scanf")


async def get_strcat(connection):
    """Retrive all usages of strcat or strncat function"""
    return await get_method_callIn(connection, "(strcat|strncat)")


async def get_strcpy(connection):
    """Retrive all usages of strcpy or strncpy function"""
    return await get_method_callIn(connection, "(strcpy|strncpy)")


async def get_strtok(connection):
    """Retrive all usages of strtok function"""
    return await get_method_callIn(connection, "strtok")
