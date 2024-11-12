
import pefile
import ntpath
from io import BytesIO
from datetime import datetime, timezone
from impacket.smbconnection import SMBConnection, SessionError
import charset_normalizer as chardet

class SMBHandler:
    def __init__(self, target, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None):
        self.connection = None
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')

    def connect(self):
        try:
            self.connection = SMBConnection(self.target, self.target)
            if self.doKerberos is True:
                self.connection.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.kdcHost)
            else:
                self.connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            return True
        except Exception as e:
            print(f"Failed to connect to {self.target}: {str(e)}")
            return False

    def list_directory(self, share, path):
        if not self.connection:
            if not self.connect():
                print(f"Failed to connect to {self.server}")
                return
        pwd = ntpath.join(path,'*')
        pwd = pwd.replace('/','\\')
        pwd = ntpath.normpath(pwd)
        try:
            files = self.connection.listPath(share, pwd)
            return files
        except Exception as e:
            return None

    def show_file_content(self, share, path, filename):
        # if self.tid is None:
        #     print("No share selected")
        #     return
        filename = filename.replace('/','\\')
        fh = BytesIO()
        pathname = ntpath.join(path,filename)
        try:
            self.connection.getFile(share, pathname, fh.write)
        except:
            raise
        output = fh.getvalue()
        encoding = chardet.detect(output)["encoding"]
        decoded_content = output.decode(encoding)
        return decoded_content

    def get_version_info(self, share, file_path):
        try:
            file_data = self.read_file_raw(share, file_path)
            return self.parse_version_info(file_data)
        except Exception as e:
            print(f"Error getting version info for {file_path}: {str(e)}")
            return None

    def read_file_raw(self, share, file_path):
        file_obj = BytesIO()
        self.connection.getFile(share, file_path, file_obj.write)
        return file_obj.getvalue()

    def read_special(self, share, file_path):
        file_obj = BytesIO()
        try:
            self.connection.getFile(share, file_path, file_obj.write)
        except SessionError as e:
            if e.getErrorCode() == 0xc0000043:  # SHARING_VIOLATION
                self.connection.getFile(share, file_path, file_obj.write, shareAccessMode=0x7)
            else:
                raise
        return file_obj.getvalue()

    def parse_version_info(self, file_data):
        try:
            pe = pefile.PE(data=file_data)
            #VersionInfo = namedtuple('VersionInfo', ['FileVersion', 'ProductVersion'])
            if hasattr(pe, 'VS_FIXEDFILEINFO'):
                file_version = (
                    f"{pe.VS_FIXEDFILEINFO[0].FileVersionMS >> 16}."
                    f"{pe.VS_FIXEDFILEINFO[0].FileVersionMS & 0xFFFF}."
                    f"{pe.VS_FIXEDFILEINFO[0].FileVersionLS >> 16}."
                    f"{pe.VS_FIXEDFILEINFO[0].FileVersionLS & 0xFFFF}"
                )
                product_version = (
                    f"{pe.VS_FIXEDFILEINFO[0].ProductVersionMS >> 16}."
                    f"{pe.VS_FIXEDFILEINFO[0].ProductVersionMS & 0xFFFF}."
                    f"{pe.VS_FIXEDFILEINFO[0].ProductVersionLS >> 16}."
                    f"{pe.VS_FIXEDFILEINFO[0].ProductVersionLS & 0xFFFF}"
                )

                #return VersionInfo(file_version, product_version)
                return product_version
            else:
                print("Version information not found in the file.")
                return None
        except pefile.PEFormatError as e:
            print(f"Error: Not a valid PE file. {str(e)}")
            return None
        except Exception as e:
            print(f"Error: {str(e)}")
            return None

    def get_last_write_time(self, share, file_path):
        if not self.connection:
            raise Exception("Not connected to SMB server. Call connect() first.")
        try:
            file_attributes = self.connection.listPath(share, file_path)
            if file_attributes:
                last_write_time = file_attributes[0].get_mtime_epoch()
                dt = datetime.fromtimestamp(last_write_time, tz=timezone.utc)
                local_dt = dt.astimezone()
                formatted_time = local_dt.strftime("%m/%d/%Y %I:%M:%S %p")
                return formatted_time
            else:
                #raise Exception(f"File not found: {file_path}")
                return None
        except Exception as e:
            return None

    def get_last_access_time(self, share, file_path):
        if not self.connection:
            raise Exception("Not connected to SMB server. Call connect() first.")
        try:
            file_attributes = self.connection.listPath(share, file_path)
            if file_attributes:
                last_access_time = file_attributes[0].get_atime_epoch()
                dt = datetime.fromtimestamp(last_access_time, tz=timezone.utc)
                local_dt = dt.astimezone()
                formatted_time = local_dt.strftime("%m/%d/%Y %I:%M:%S %p")
                return formatted_time
            else:
                return None
        except Exception as e:
            return None

    def get_file_size(self, share, file_path):
        if not self.connection:
            raise Exception("Not connected to SMB server. Call connect() first.")
        try:
            file_attributes = self.connection.listPath(share, file_path)
            if file_attributes:
                return file_attributes[0].get_filesize()
            else:
                return None
        except Exception as e:
            print(f"Error getting file size for {file_path}: {str(e)}")
            return None
        
    def file_exists(self, share, file_path):
        if not self.connection:
            raise Exception("Not connected to SMB server. Call connect() first.")
        try:
            self.connection.listPath(share, file_path)
            return True
        except Exception as e:
            return False

    def close(self):
        if self.connection:
            self.connection.close()
