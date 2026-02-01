"""
JSON-based caching system for security assessments
"""
import json
import os
from datetime import datetime, timedelta
import threading
from typing import Dict, Any, List, Optional


class JSONCache:
    """Simple JSON-based cache for storing assessment results"""
    
    def __init__(self, cache_file='data/cache.json', default_expiry_hours=720):
        """
        Initialize the JSON cache
        
        Args:
            cache_file: Path to the JSON cache file
            default_expiry_hours: Default expiry time in hours (default: 720 hours = 30 days)
        """
        self.cache_file = cache_file
        self.default_expiry_hours = default_expiry_hours  # 30 days default
        self.lock = threading.Lock()
        
        # Ensure cache directory exists
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        
        # Initialize cache file if it doesn't exist
        if not os.path.exists(cache_file):
            self._write_cache({'assessments': [], 'raw_data': {}})
        else:
            # Clean up expired entries on initialization
            self._cleanup_on_init()
    
    def _read_cache(self):
        """Read the cache file"""
        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {'assessments': [], 'raw_data': {}}
    
    def _write_cache(self, data):
        """Write to the cache file"""
        with open(self.cache_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _normalize(self, text):
        """Normalize text for comparison"""
        if not text:
            return ""
        return text.lower().strip()
    
    def _cleanup_on_init(self):
        """Remove expired entries on initialization"""
        try:
            with self.lock:
                cache_data = self._read_cache()
                assessments = cache_data.get('assessments', [])
                raw_data = cache_data.get('raw_data', {})
                
                now = datetime.now()
                valid_assessments = []
                removed_assessments = 0
                
                # Remove assessments older than default_expiry_hours (30 days)
                for assessment in assessments:
                    timestamp_str = assessment.get('created_at') or assessment.get('timestamp')
                    if timestamp_str:
                        try:
                            cached_time = datetime.fromisoformat(timestamp_str)
                            age = now - cached_time
                            if age <= timedelta(hours=self.default_expiry_hours):
                                valid_assessments.append(assessment)
                            else:
                                removed_assessments += 1
                        except:
                            # Keep if we can't parse the timestamp
                            valid_assessments.append(assessment)
                    else:
                        # Keep if no timestamp
                        valid_assessments.append(assessment)
                
                # Remove expired raw_data
                valid_raw_data = {}
                removed_raw = 0
                for key, entry in raw_data.items():
                    if 'expires_at' in entry:
                        try:
                            expires_at = datetime.fromisoformat(entry['expires_at'])
                            if now <= expires_at:
                                valid_raw_data[key] = entry
                            else:
                                removed_raw += 1
                        except:
                            # Keep if we can't parse
                            valid_raw_data[key] = entry
                    else:
                        # Keep if no expiry date
                        valid_raw_data[key] = entry
                
                # Only write if we removed something
                if removed_assessments > 0 or removed_raw > 0:
                    cache_data['assessments'] = valid_assessments
                    cache_data['raw_data'] = valid_raw_data
                    self._write_cache(cache_data)
                    print(f"[CACHE] Cleaned up {removed_assessments} expired assessments and {removed_raw} expired raw data entries")
        except Exception as e:
            # Don't crash on cleanup errors
            print(f"[CACHE] Warning: Could not clean up cache: {e}")
    
    def get_assessment(self, product_name=None, vendor=None, max_age_hours=None):
        """
        Get assessment by product name or vendor (exact match)
        
        Args:
            product_name: Product name to search for
            vendor: Vendor name to search for
            max_age_hours: Maximum age in hours (None = use default)
            
        Returns:
            Assessment dict if found and not expired, None otherwise
        """
        if max_age_hours is None:
            max_age_hours = self.default_expiry_hours
        
        with self.lock:
            cache_data = self._read_cache()
            assessments = cache_data.get('assessments', [])
            
            normalized_product = self._normalize(product_name) if product_name else ""
            normalized_vendor = self._normalize(vendor) if vendor else ""
            
            for assessment in assessments:
                # Check expiry using created_at or timestamp
                timestamp_str = assessment.get('created_at') or assessment.get('timestamp')
                if timestamp_str:
                    try:
                        cached_time = datetime.fromisoformat(timestamp_str)
                        age = datetime.now() - cached_time
                        if age > timedelta(hours=max_age_hours):
                            continue
                    except:
                        pass
                
                # Get cached values from top-level cache entry
                cached_product = self._normalize(assessment.get('product_name', ''))
                cached_vendor = self._normalize(assessment.get('vendor', ''))
                
                # Match on product name if provided (exact match)
                if normalized_product and (normalized_product == cached_product):
                    return assessment.get('result', assessment)
                
                # Match on vendor if provided (and no product specified)
                if normalized_vendor and not normalized_product and (normalized_vendor == cached_vendor):
                    return assessment.get('result', assessment)
            
            return None
    
    def get_assessment_by_query(self, query, max_age_hours=None):
        """
        Get assessment by search query with fuzzy matching
        
        Args:
            query: Search query (product name, vendor, etc.)
            max_age_hours: Maximum age in hours (None = use default)
            
        Returns:
            Assessment dict if found and not expired, None otherwise
        """
        if max_age_hours is None:
            max_age_hours = self.default_expiry_hours
        
        with self.lock:
            cache_data = self._read_cache()
            assessments = cache_data.get('assessments', [])
            
            normalized_query = self._normalize(query)
            
            for assessment in assessments:
                # Check expiry
                timestamp_str = assessment.get('created_at') or assessment.get('timestamp')
                if timestamp_str:
                    try:
                        cached_time = datetime.fromisoformat(timestamp_str)
                        age = datetime.now() - cached_time
                        if age > timedelta(hours=max_age_hours):
                            continue
                    except:
                        pass
                
                # Get cached values from top-level cache entry
                product_name = self._normalize(assessment.get('product_name', ''))
                vendor = self._normalize(assessment.get('vendor', ''))
                cached_query = self._normalize(assessment.get('query', ''))
                
                # Check if query exactly matches the stored query
                if cached_query and normalized_query == cached_query:
                    return assessment.get('result', assessment)
                
                # Check if query exactly matches product name
                if product_name and normalized_query == product_name:
                    return assessment.get('result', assessment)
                
                # Check if query exactly matches vendor
                if vendor and normalized_query == vendor:
                    return assessment.get('result', assessment)
                
                # Fuzzy match: query fully contained in product name or vice versa
                # (but both must have reasonable length to avoid false positives)
                if product_name and len(normalized_query) >= 5 and len(product_name) >= 5:
                    if normalized_query in product_name or product_name in normalized_query:
                        return assessment.get('result', assessment)
                    
                # Fuzzy match: query fully contained in vendor or vice versa
                if vendor and len(normalized_query) >= 5 and len(vendor) >= 5:
                    if normalized_query in vendor or vendor in normalized_query:
                        return assessment.get('result', assessment)
            
            return None
    
    def get_assessment_by_id(self, assessment_id):
        """
        Get assessment by ID
        
        Args:
            assessment_id: The ID of the assessment
            
        Returns:
            Assessment dict if found, None otherwise
        """
        with self.lock:
            cache_data = self._read_cache()
            assessments = cache_data.get('assessments', [])
            
            for assessment in assessments:
                if assessment.get('id') == assessment_id:
                    return assessment.get('result', assessment)
            
            return None
    
    def save_assessment(self, product_name=None, assessment_data=None, vendor=None, url=None, search_term=None):
        """
        Save or update an assessment
        
        Args:
            product_name: Product name (for compatibility)
            assessment_data: Assessment dict to save
            vendor: Vendor name (for compatibility)
            url: URL (for compatibility)
            search_term: Search term (for compatibility)
            
        Returns:
            The assessment ID
        """
        # Handle both old and new calling conventions
        if assessment_data is None and isinstance(product_name, dict):
            # New style: save_assessment(assessment_data)
            assessment_data = product_name
            product_name = None
        
        if assessment_data is None:
            raise ValueError("assessment_data is required")
        
        with self.lock:
            cache_data = self._read_cache()
            assessments = cache_data.get('assessments', [])
            
            # Extract entity info from assessment_data for the cache entry
            entity = assessment_data.get('entity', {})
            metadata = assessment_data.get('metadata', {})
            
            # Use provided values or extract from assessment
            final_product_name = product_name or entity.get('product_name')
            final_vendor = vendor or entity.get('vendor')
            final_url = url or entity.get('url')
            final_query = search_term or final_product_name or final_vendor
            
            # Build cache entry structure matching existing format
            cache_entry = {
                'query': final_query,
                'product_name': final_product_name,
                'vendor': final_vendor,
                'url': final_url,
                'created_at': datetime.now().isoformat(),
                'timestamp': metadata.get('timestamp', datetime.now().isoformat()),
                'product_name_norm': self._normalize(final_product_name),
                'vendor_norm': self._normalize(final_vendor),
                'result': assessment_data
            }
            
            # Generate ID
            max_id = max([a.get('id', 0) for a in assessments], default=0)
            cache_entry['id'] = max_id + 1
            
            # Append new entry
            assessments.append(cache_entry)
            
            cache_data['assessments'] = assessments
            self._write_cache(cache_data)
            
            return cache_entry['id']
    
    def get_all_assessments(self, limit=None):
        """
        Get all assessments
        
        Args:
            limit: Maximum number of assessments to return (None = all)
            
        Returns:
            List of assessments sorted by timestamp (newest first)
        """
        with self.lock:
            cache_data = self._read_cache()
            assessments = cache_data.get('assessments', [])
            
            # Sort by timestamp (newest first)
            sorted_assessments = sorted(
                assessments,
                key=lambda x: x.get('created_at') or x.get('timestamp', ''),
                reverse=True
            )
            
            if limit:
                return sorted_assessments[:limit]
            return sorted_assessments
    
    def get_raw_data(self, key: str) -> Optional[Any]:
        """
        Get raw cached data (CVEs, KEVs, ProductHunt data, etc.)
        
        Args:
            key: Cache key
            
        Returns:
            Cached data if found and not expired, None otherwise
        """
        with self.lock:
            cache_data = self._read_cache()
            raw_data = cache_data.get('raw_data', {})
            
            if key in raw_data:
                entry = raw_data[key]
                
                # Check expiry
                if 'expires_at' in entry:
                    try:
                        expires_at = datetime.fromisoformat(entry['expires_at'])
                        if datetime.now() > expires_at:
                            return None
                    except:
                        pass
                
                return entry.get('data')
            
            return None
    
    def save_raw_data(self, key: str, data_type: str, data: Any, expiry_hours: int = 720):
        """
        Save raw data to cache
        
        Args:
            key: Cache key
            data_type: Type of data (e.g., 'cve', 'kev', 'producthunt')
            data: Data to cache
            expiry_hours: Expiry time in hours (default: 720 hours = 30 days)
        """
        with self.lock:
            cache_data = self._read_cache()
            
            if 'raw_data' not in cache_data:
                cache_data['raw_data'] = {}
            
            cache_data['raw_data'][key] = {
                'data_type': data_type,
                'data': data,
                'cached_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(hours=expiry_hours)).isoformat()
            }
            
            self._write_cache(cache_data)
    
    def clear_expired(self, max_age_hours=None):
        """
        Remove expired assessments and raw data
        
        Args:
            max_age_hours: Maximum age in hours (None = use default)
            
        Returns:
            Number of items removed
        """
        if max_age_hours is None:
            max_age_hours = self.default_expiry_hours
        
        with self.lock:
            cache_data = self._read_cache()
            assessments = cache_data.get('assessments', [])
            raw_data = cache_data.get('raw_data', {})
            
            now = datetime.now()
            valid_assessments = []
            removed_count = 0
            
            # Clean assessments
            for assessment in assessments:
                timestamp_str = assessment.get('created_at') or assessment.get('timestamp')
                if timestamp_str:
                    try:
                        cached_time = datetime.fromisoformat(timestamp_str)
                        age = now - cached_time
                        if age <= timedelta(hours=max_age_hours):
                            valid_assessments.append(assessment)
                        else:
                            removed_count += 1
                    except:
                        valid_assessments.append(assessment)
                else:
                    valid_assessments.append(assessment)
            
            # Clean raw_data
            valid_raw_data = {}
            for key, entry in raw_data.items():
                if 'expires_at' in entry:
                    try:
                        expires_at = datetime.fromisoformat(entry['expires_at'])
                        if now <= expires_at:
                            valid_raw_data[key] = entry
                        else:
                            removed_count += 1
                    except:
                        valid_raw_data[key] = entry
                else:
                    valid_raw_data[key] = entry
            
            cache_data['assessments'] = valid_assessments
            cache_data['raw_data'] = valid_raw_data
            self._write_cache(cache_data)
            
            return removed_count
    
    def clear_all(self):
        """Clear all cached assessments and raw data"""
        with self.lock:
            self._write_cache({'assessments': [], 'raw_data': {}})
    
    def delete_assessment(self, assessment_id: int):
        """
        Delete a specific assessment by ID
        
        Args:
            assessment_id: The ID of the assessment to delete
            
        Returns:
            True if deleted, False if not found
        """
        with self.lock:
            cache_data = self._read_cache()
            assessments = cache_data.get('assessments', [])
            
            # Find and remove the assessment
            for i, assessment in enumerate(assessments):
                if assessment.get('id') == assessment_id:
                    assessments.pop(i)
                    cache_data['assessments'] = assessments
                    self._write_cache(cache_data)
                    return True
            
            return False
