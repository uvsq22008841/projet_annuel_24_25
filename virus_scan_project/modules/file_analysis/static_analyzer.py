# modules/file_analysis/static_analyzer.py
import os
import re
import magic
import pefile
import hashlib
import zipfile
import olefile
import yara

class StaticAnalyzer:
    def __init__(self, rules_dir="rules"):
        self.mime_analyzer = magic.Magic(mime=True)
        self.yara_rules = {}
        self._load_yara_rules(rules_dir)
        
    def _load_yara_rules(self, rules_dir):
        """Charge les règles YARA depuis un répertoire"""
        if not os.path.exists(rules_dir):
            os.makedirs(rules_dir)
            
        for filename in os.listdir(rules_dir):
            if filename.endswith('.yar') or filename.endswith('.yara'):
                rule_path = os.path.join(rules_dir, filename)
                try:
                    rule_name = os.path.splitext(filename)[0]
                    self.yara_rules[rule_name] = yara.compile(rule_path)
                except Exception as e:
                    print(f"Erreur lors du chargement de la règle {filename}: {e}")
    
    def analyze_file(self, file_path):
        """Analyse statique complète d'un fichier"""
        results = {
            "basic_info": self._get_basic_info(file_path),
            "hashes": self._calculate_hashes(file_path),
            "strings": self._extract_strings(file_path),
            "yara_matches": self._check_yara_rules(file_path),
            "format_specific": {}
        }
        
        # Analyse spécifique en fonction du type de fichier
        mime_type = results["basic_info"]["mime_type"]
        
        if "application/x-dosexec" in mime_type:
            results["format_specific"]["pe"] = self._analyze_pe(file_path)
        elif "application/zip" in mime_type:
            results["format_specific"]["zip"] = self._analyze_zip(file_path)
        elif "application/x-ole-storage" in mime_type:
            results["format_specific"]["ole"] = self._analyze_ole(file_path)
        elif "application/pdf" in mime_type:
            results["format_specific"]["pdf"] = self._analyze_pdf(file_path)
        
        # Déterminer le niveau de risque en fonction des résultats
        results["risk_assessment"] = self._assess_risk(results)
        
        return results
    
    def _get_basic_info(self, file_path):
        """Obtient les informations de base sur le fichier"""
        stat_info = os.stat(file_path)
        mime_type = self.mime_analyzer.from_file(file_path)
        
        return {
            "file_name": os.path.basename(file_path),
            "file_size": stat_info.st_size,
            "creation_time": stat_info.st_ctime,
            "modification_time": stat_info.st_mtime,
            "mime_type": mime_type,
            "extension": os.path.splitext(file_path)[1]
        }
    
    def _calculate_hashes(self, file_path):
        """Calcule différentes empreintes cryptographiques"""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            data = f.read()
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
        
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest()
        }
    
    def _extract_strings(self, file_path, min_length=4):
        """Extrait les chaînes ASCII et Unicode du fichier"""
        ascii_strings = []
        unicode_strings = []
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Extraction de chaînes ASCII
        ascii_pattern = re.compile(b'[\x20-\x7E]{%d,}' % min_length)
        ascii_strings = [match.group().decode('ascii') for match in ascii_pattern.finditer(data)]
        
        # Extraction de chaînes Unicode
        unicode_pattern = re.compile(b'(?:[\x20-\x7E]\x00){%d,}' % min_length)
        unicode_matches = [match.group() for match in unicode_pattern.finditer(data)]
        unicode_strings = [match.decode('utf-16le') for match in unicode_matches]
        
        return {
            "ascii": ascii_strings,
            "unicode": unicode_strings,
            "potential_urls": self._extract_urls(ascii_strings + unicode_strings),
            "potential_ips": self._extract_ips(ascii_strings + unicode_strings),
            "potential_domains": self._extract_domains(ascii_strings + unicode_strings),
            "potential_emails": self._extract_emails(ascii_strings + unicode_strings)
        }
    
    def _extract_urls(self, strings):
        """Extrait les URLs potentielles des chaînes"""
        url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
        urls = []
        
        for s in strings:
            urls.extend(url_pattern.findall(s))
        
        return list(set(urls))
    
    def _extract_ips(self, strings):
        """Extrait les adresses IP potentielles des chaînes"""
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ips = []
        
        for s in strings:
            ips.extend(ip_pattern.findall(s))
        
        return list(set(ips))
    
    def _extract_domains(self, strings):
        """Extrait les noms de domaine potentiels des chaînes"""
        domain_pattern = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE)
        domains = []
        
        for s in strings:
            domains.extend(domain_pattern.findall(s))
        
        return list(set(domains))
    
    def _extract_emails(self, strings):
        """Extrait les adresses email potentielles des chaînes"""
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        emails = []
        
        for s in strings:
            emails.extend(email_pattern.findall(s))
        
        return list(set(emails))
    
    def _check_yara_rules(self, file_path):
        """Vérifie le fichier contre les règles YARA chargées"""
        matches = {}
        
        for rule_name, rule in self.yara_rules.items():
            try:
                rule_matches = rule.match(file_path)
                if rule_matches:
                    matches[rule_name] = [match.rule for match in rule_matches]
            except Exception as e:
                matches[rule_name] = {"error": str(e)}
        
        return matches
    
    def _analyze_pe(self, file_path):
        """Analyse spécifique pour les fichiers PE (Windows executables)"""
        try:
            pe = pefile.PE(file_path)
            sections = []
            
            for section in pe.sections:
                sections.append({
                    "name": section.Name.decode('utf-8').rstrip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "size": section.SizeOfRawData,
                    "entropy": section.get_entropy()
                })
            
            imports = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8')
                    imports[dll_name] = []
                    
                    for imp in entry.imports:
                        if imp.name:
                            imports[dll_name].append(imp.name.decode('utf-8'))
                        else:
                            imports[dll_name].append(f"Ordinal: {imp.ordinal}")
            
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8'))
                    else:
                        exports.append(f"Ordinal: {exp.ordinal}")
            
            return {
                "is_dll": pe.is_dll(),
                "is_exe": pe.is_exe(),
                "machine_type": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine),
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "sections": sections,
                "imports": imports,
                "exports": exports,
                "resources": self._analyze_pe_resources(pe),
                "suspicious_indicators": self._check_pe_suspicious(pe)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_pe_resources(self, pe):
        """Analyse les ressources d'un fichier PE"""
        resources = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = pefile.RESOURCE_TYPE.get(resource_type.id, str(resource_type.id))
                
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        resources.append({
                            "type": type_name,
                            "id": resource_id.id,
                            "language": resource_lang.id,
                            "size": resource_lang.data.struct.Size
                        })
        
        return resources
    
    def _check_pe_suspicious(self, pe):
        """Vérifie les indicateurs suspects dans un fichier PE"""
        suspicious = []
        
        # Vérifier les sections avec une entropie élevée (possible packer/crypteur)
        for section in pe.sections:
            if section.get_entropy() > 7.0:
                suspicious.append(f"Section {section.Name.decode('utf-8').rstrip('\x00')} a une entropie très élevée ({section.get_entropy():.2f})")
        
        # Vérifier les imports suspects
        suspicious_imports = ["URLDownloadToFile", "WinExec", "ShellExecute", 
                             "CreateRemoteThread", "VirtualAlloc", "VirtualProtect",
                             "WriteProcessMemory", "ReadProcessMemory"]
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imp_name = imp.name.decode('utf-8')
                        if any(susp_imp in imp_name for susp_imp in suspicious_imports):
                            suspicious.append(f"Import suspect trouvé: {imp_name} dans {entry.dll.decode('utf-8')}")
        
        return suspicious
    
    def _analyze_zip(self, file_path):
        """Analyse spécifique pour les fichiers ZIP"""
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                info_list = zip_file.infolist()
                files = []
                
                for info in info_list:
                    files.append({
                        "filename": info.filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "date_time": f"{info.date_time[0]}-{info.date_time[1]}-{info.date_time[2]} {info.date_time[3]}:{info.date_time[4]}:{info.date_time[5]}",
                        "is_encrypted": info.flag_bits & 0x1
                    })
                
                return {
                    "file_count": len(files),
                    "files": files,
                    "comment": zip_file.comment.decode('utf-8', errors='ignore') if zip_file.comment else None,
                    "suspicious_indicators": self._check_zip_suspicious(files)
                }
        except Exception as e:
            return {"error": str(e)}
    
    def _check_zip_suspicious(self, files):
        """Vérifie les indicateurs suspects dans un fichier ZIP"""
        suspicious = []
        
        # Vérifier les extensions de fichiers suspects
        suspicious_exts = ['.exe', '.dll', '.bat', '.cmd', '.js', '.vbs', '.ps1', '.hta', '.jar']
        for file in files:
            ext = os.path.splitext(file["filename"])[1].lower()
            if ext in suspicious_exts:
                suspicious.append(f"Fichier suspect trouvé: {file['filename']}")
        
        # Vérifier les fichiers cachés ou en profondeur
        for file in files:
            if file["filename"].startswith("__MACOSX") or file["filename"].startswith("._"):
                suspicious.append(f"Fichier potentiellement caché: {file['filename']}")
            
            if file["filename"].count('/') > 5:
                suspicious.append(f"Fichier dans une arborescence profonde: {file['filename']}")
        
        # Vérifier les fichiers chiffrés
        encrypted_count = sum(1 for file in files if file["is_encrypted"])
        if encrypted_count > 0:
            suspicious.append(f"Archive contient {encrypted_count} fichier(s) chiffré(s)")
        
        return suspicious
    
    def _analyze_ole(self, file_path):
        """Analyse spécifique pour les fichiers OLE (MS Office)"""
        try:
            ole = olefile.OleFile(file_path)
            streams = []
            
            for stream in ole.listdir():
                stream_path = '/'.join(stream)
                stream_size = ole.get_size(stream_path)
                
                streams.append({
                    "name": stream_path,
                    "size": stream_size
                })
            
            metadata = {}
            if ole.exists('\x05DocumentSummaryInformation'):
                docsum = ole.getproperties('\x05DocumentSummaryInformation')
                for prop_id, prop_value in docsum.items():
                    metadata[f"DocSum_{prop_id}"] = str(prop_value)
            
            if ole.exists('\x05SummaryInformation'):
                summary = ole.getproperties('\x05SummaryInformation')
                for prop_id, prop_value in summary.items():
                    metadata[f"Summary_{prop_id}"] = str(prop_value)
            
            return {
                "has_macros": self._check_ole_macros(ole),
                "streams": streams,
                "metadata": metadata,
                "suspicious_indicators": self._check_ole_suspicious(ole, streams)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _check_ole_macros(self, ole):
        """Vérifie si un fichier OLE contient des macros"""
        macro_streams = ['Macros', 'VBA', '_VBA_PROJECT']
        
        for stream in ole.listdir():
            stream_path = '/'.join(stream).lower()
            if any(macro in stream_path for macro in macro_streams):
                return True
        
        return False
    
    def _check_ole_suspicious(self, ole, streams):
        """Vérifie les indicateurs suspects dans un fichier OLE"""
        suspicious = []
        
        # Vérifier la présence de macros
        if self._check_ole_macros(ole):
            suspicious.append("Le document contient des macros")
        
        # Vérifier la présence d'objets OLE suspects
        for stream in streams:
            if "ole" in stream["name"].lower() or "object" in stream["name"].lower():
                suspicious.append(f"Objet OLE potentiellement incorporé: {stream['name']}")
        
        # Vérifier la présence de DDE
        for stream in streams:
            if "dde" in stream["name"].lower():
                suspicious.append(f"Lien DDE potentiel: {stream['name']}")
        
        return suspicious
    
    def _analyze_pdf(self, file_path):
        """Analyse spécifique pour les fichiers PDF"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Recherche de modèles suspects dans le PDF
            javascript_count = data.count(b'/JavaScript')
            openaction_count = data.count(b'/OpenAction')
            launch_count = data.count(b'/Launch')
            jbig2decode_count = data.count(b'/JBIG2Decode')
            richmedia_count = data.count(b'/RichMedia')
            
            return {
                "version": self._extract_pdf_version(data),
                "object_count": data.count(b'obj'),
                "features": {
                    "javascript": javascript_count > 0,
                    "javascript_count": javascript_count,
                    "openaction": openaction_count > 0,
                    "openaction_count": openaction_count,
                    "launch": launch_count > 0,
                    "launch_count": launch_count,
                    "jbig2decode": jbig2decode_count > 0,
                    "jbig2decode_count": jbig2decode_count,
                    "richmedia": richmedia_count > 0,
                    "richmedia_count": richmedia_count
                },
                "suspicious_indicators": self._check_pdf_suspicious(data)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_pdf_version(self, data):
        """Extrait la version d'un PDF"""
        match = re.search(b'%PDF-(\d+\.\d+)', data)
        if match:
            return match.group(1).decode('ascii')
        return "Unknown"
    
    def _check_pdf_suspicious(self, data):
        """Vérifie les indicateurs suspects dans un fichier PDF"""
        suspicious = []
        
        # Vérifier la présence de JavaScript
        if data.count(b'/JavaScript') > 0:
            suspicious.append("Le PDF contient du JavaScript")
        
        # Vérifier la présence de actions automatiques
        if data.count(b'/OpenAction') > 0:
            suspicious.append("Le PDF contient des actions automatiques (OpenAction)")
        
        # Vérifier la présence d'exécution de commandes
        if data.count(b'/Launch') > 0:
            suspicious.append("Le PDF contient des commandes d'exécution (Launch)")
        
        # Vérifier la présence de décodeurs suspects
        if data.count(b'/JBIG2Decode') > 0:
            suspicious.append("Le PDF utilise le décodeur JBIG2 (potentiellement exploitable)")
        
        # Vérifier la présence d'objets multimédia
        if data.count(b'/RichMedia') > 0:
            suspicious.append("Le PDF contient des objets multimédia riches")
        
        # Vérifier la présence d'encodage inhabituel
        encodings = [b'/ASCIIHexDecode', b'/ASCII85Decode', b'/LZWDecode', b'/FlateDecode', 
                     b'/RunLengthDecode', b'/CCITTFaxDecode']
        
        for encoding in encodings:
            if data.count(encoding) > 0:
                suspicious.append(f"Le PDF utilise l'encodage {encoding.decode('ascii')}")
        
        return suspicious
    
    def _assess_risk(self, results):
        """Évalue le niveau de risque global en fonction des résultats d'analyse"""
        risk_score = 0
        risk_factors = []
        
        # Vérifier les correspondances YARA
        yara_matches = results.get("yara_matches", {})
        for rule_name, matches in yara_matches.items():
            if isinstance(matches, list) and len(matches) > 0:
                risk_score += 25
                risk_factors.append(f"Correspondance avec la règle YARA {rule_name}")
        
        # Vérifier les chaînes suspectes
        strings = results.get("strings", {})
        if len(strings.get("potential_urls", [])) > 5:
            risk_score += 5
            risk_factors.append("Nombre élevé d'URLs trouvées")
        
        if len(strings.get("potential_ips", [])) > 5:
            risk_score += 5
            risk_factors.append("Nombre élevé d'adresses IP trouvées")
        
        # Vérifier les indicateurs spécifiques au format
        format_specific = results.get("format_specific", {})
        
        if "pe" in format_specific:
            pe_data = format_specific["pe"]
            if isinstance(pe_data, dict) and not pe_data.get("error"):
                suspicious = pe_data.get("suspicious_indicators", [])
                risk_score += len(suspicious) * 5
                risk_factors.extend(suspicious)
        
        if "ole" in format_specific:
            ole_data = format_specific["ole"]
            if isinstance(ole_data, dict) and not ole_data.get("error"):
                if ole_data.get("has_macros", False):
                    risk_score += 15
                    risk_factors.append("Le document contient des macros")
                
                suspicious = ole_data.get("suspicious_indicators", [])
                risk_score += len(suspicious) * 5
                risk_factors.extend(suspicious)
        
        if "pdf" in format_specific:
            pdf_data = format_specific["pdf"]
            if isinstance(pdf_data, dict) and not pdf_data.get("error"):
                features = pdf_data.get("features", {})
                
                if features.get("javascript", False):
                    risk_score += 15
                    risk_factors.append("Le PDF contient du JavaScript")
                
                if features.get("openaction", False):
                    risk_score += 10
                    risk_factors.append("Le PDF contient des actions automatiques")
                
                if features.get("launch", False):
                    risk_score += 20
                    risk_factors.append("Le PDF contient des commandes d'exécution")
                
                suspicious = pdf_data.get("suspicious_indicators", [])
                risk_score += len(suspicious) * 5
                risk_factors.extend(suspicious)
        
        # Déterminer le niveau de risque
        risk_level = "Faible"
        if risk_score > 20:
            risk_level = "Moyen"
        if risk_score > 40:
            risk_level = "Élevé"
        if risk_score > 60:
            risk_level = "Critique"
        
        return {
            "score": risk_score,
            "level": risk_level,
            "factors": risk_factors
        }