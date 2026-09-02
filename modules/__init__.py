from modules.recon import ReconModule
from modules.http_methods import HTTPMethodsModule
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
from modules.csrf import CSRFModule
from modules.cors import CORSModule
from modules.cors_differential import CORSDifferentialModule
from modules.security_headers import SecurityHeadersModule
from modules.bypass403 import Bypass403Module
from modules.backup_files import BackupSensitiveFilesModule
from modules.graphql import GraphQLModule
from modules.host_header import HostHeaderModule
from modules.cache import CacheModule
from modules.websocket import WebSocketModule
from modules.advanced_http import AdvancedHTTPModule
from modules.business_logic import BusinessLogicModule
from modules.api_mass_assignment import APIMassAssignmentModule
from modules.advanced_inventory import AdvancedInventoryModule
from modules.deep_payload_matrix import DeepPayloadMatrixModule
from modules.upload_documents import DocumentUploadModule

ALL_MODULES = [
    ReconModule, HTTPMethodsModule, OldSessionsModule, SQLiModule, IDORModule, LFIModule, SSTIModule,
    XSSModule, SSRFModule, XXEModule, RCEModule, FileUploadModule, OpenRedirectModule,
    AuthBypassModule, NoSQLModule, JWTModule, PrototypePollutionModule, HPPModule, CSRFModule,
    CORSModule, CORSDifferentialModule, SecurityHeadersModule,
    Bypass403Module, BackupSensitiveFilesModule, GraphQLModule, HostHeaderModule, CacheModule,
    WebSocketModule, AdvancedHTTPModule, BusinessLogicModule, APIMassAssignmentModule, AdvancedInventoryModule, DeepPayloadMatrixModule, DocumentUploadModule,
]
