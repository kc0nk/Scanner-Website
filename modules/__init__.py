from modules.recon import ReconModule
from modules.old_sessions import OldSessionsModule
from modules.sqli import SQLiModule
from modules.idor import IDORModule
from modules.lfi import LFIModule
from modules.ssti import SSTIModule
from modules.xss import XSSModule
from modules.ssrf import SSRFModule
from modules.xxe import XXEModule
from modules.rce import RCEModule
from modules.upload import FileUploadModule
from modules.open_redirect import OpenRedirectModule
from modules.auth_bypass import AuthBypassModule
from modules.nosql import NoSQLModule
from modules.jwt import JWTModule
from modules.prototype import PrototypePollutionModule
from modules.hpp import HPPModule

ALL_MODULES = [
    ReconModule, OldSessionsModule, SQLiModule, IDORModule, LFIModule, SSTIModule,
    XSSModule, SSRFModule, XXEModule, RCEModule, FileUploadModule, OpenRedirectModule,
    AuthBypassModule, NoSQLModule, JWTModule, PrototypePollutionModule, HPPModule,
]
