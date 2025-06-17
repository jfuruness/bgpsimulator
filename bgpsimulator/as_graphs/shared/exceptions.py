class CycleError(RuntimeError):
    pass

class NoCAIDAURLError(Exception):
    """Raised when no CAIDA URL is found"""
    pass