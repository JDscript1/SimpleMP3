#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Performance Optimizer pentru SimpleMP3 Converter
"""

import os
import time
import hashlib
import threading
from typing import Optional, Tuple, Dict, Any

class PerformanceOptimizer:
    """Optimizator de performanță pentru conversii"""
    
    def __init__(self):
        self.cache_dir = "cache"
        self.metrics = {
            'total_conversions': 0,
            'conversions': [],
            'cache_hits': 0,
            'cache_misses': 0
        }
        self.monitoring = False
        self.monitor_thread = None
        
        # Creează directorul cache dacă nu există
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
    
    def check_cache(self, url: str, quality: str, format_type: str) -> Tuple[Optional[str], Optional[int], Optional[float]]:
        """Verifică dacă există un fișier în cache"""
        cache_key = self._generate_cache_key(url, quality, format_type)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.mp3")
        
        if os.path.exists(cache_file):
            self.metrics['cache_hits'] += 1
            file_size = os.path.getsize(cache_file)
            return cache_file, file_size, 0.0
        else:
            self.metrics['cache_misses'] += 1
            return None, None, None
    
    def _generate_cache_key(self, url: str, quality: str, format_type: str) -> str:
        """Generează o cheie unică pentru cache"""
        content = f"{url}_{quality}_{format_type}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def optimize_yt_dlp_settings(self, base_settings: Dict[str, Any]) -> Dict[str, Any]:
        """Optimizează setările yt-dlp"""
        optimized = base_settings.copy()
        
        # Optimizări pentru performanță
        optimized.update({
            'nocheckcertificate': True,
            'ignoreerrors': True,
            'no_warnings': True,
            'extractaudio': True,
            'audioformat': 'mp3',
            'audioquality': '192K',
        })
        
        return optimized
    
    def add_to_cache(self, url: str, quality: str, format_type: str, file_path: str):
        """Adaugă un fișier în cache"""
        try:
            cache_key = self._generate_cache_key(url, quality, format_type)
            cache_file = os.path.join(self.cache_dir, f"{cache_key}.mp3")
            
            # Copiază fișierul în cache
            import shutil
            shutil.copy2(file_path, cache_file)
        except Exception as e:
            print(f"Eroare la adăugarea în cache: {e}")
    
    def start_resource_monitoring(self):
        """Pornește monitorizarea resurselor"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
            self.monitor_thread.start()
    
    def stop_resource_monitoring(self):
        """Oprește monitorizarea resurselor"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
    
    def _monitor_resources(self):
        """Monitorizează resursele sistemului"""
        while self.monitoring:
            try:
                # Monitorizare simplă - poate fi extinsă
                time.sleep(30)
            except Exception as e:
                print(f"Eroare la monitorizarea resurselor: {e}")
                break
    
    def get_metrics(self) -> Dict[str, Any]:
        """Returnează metricile de performanță"""
        return self.metrics.copy()
    
    def clear_cache(self):
        """Șterge cache-ul"""
        try:
            import shutil
            if os.path.exists(self.cache_dir):
                shutil.rmtree(self.cache_dir)
                os.makedirs(self.cache_dir)
        except Exception as e:
            print(f"Eroare la ștergerea cache-ului: {e}")
