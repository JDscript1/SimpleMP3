// Service Worker pentru SimpleMP3 Converter
// Cache offline și performanță îmbunătățită

const CACHE_NAME = 'youtube-converter-v1.0.0';
const STATIC_CACHE = 'static-v1.0.0';
const DYNAMIC_CACHE = 'dynamic-v1.0.0';

// Fișiere esențiale pentru cache
const STATIC_FILES = [
    '/',
    '/static/css/style.css',
    '/static/js/app.js',
    '/static/images/logo.png',
    '/static/fonts/roboto.woff2',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css'
];

// API endpoints pentru cache
const API_ENDPOINTS = [
    '/api/stats',
    '/api/settings'
];

// Install event - cache fișierele statice
self.addEventListener('install', event => {
    console.log('🔧 Service Worker: Installing...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then(cache => {
                console.log('📦 Service Worker: Caching static files');
                return cache.addAll(STATIC_FILES);
            })
            .then(() => {
                console.log('✅ Service Worker: Static files cached');
                return self.skipWaiting();
            })
            .catch(error => {
                console.error('❌ Service Worker: Cache failed', error);
            })
    );
});

// Activate event - cleanup cache-uri vechi
self.addEventListener('activate', event => {
    console.log('🚀 Service Worker: Activating...');
    
    event.waitUntil(
        caches.keys()
            .then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => {
                        if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
                            console.log('🗑️ Service Worker: Deleting old cache', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
            .then(() => {
                console.log('✅ Service Worker: Activated');
                return self.clients.claim();
            })
    );
});

// Fetch event - cache strategy
self.addEventListener('fetch', event => {
    const { request } = event;
    const url = new URL(request.url);
    
    // Skip non-GET requests
    if (request.method !== 'GET') {
        return;
    }
    
    // Skip chrome-extension requests
    if (url.protocol === 'chrome-extension:') {
        return;
    }
    
    event.respondWith(handleRequest(request));
});

async function handleRequest(request) {
    const url = new URL(request.url);
    
    try {
        // Cache strategy pentru fișiere statice
        if (isStaticFile(url.pathname)) {
            return await cacheFirst(request);
        }
        
        // Cache strategy pentru API calls
        if (url.pathname.startsWith('/api/')) {
            return await networkFirst(request);
        }
        
        // Cache strategy pentru HTML
        if (request.headers.get('accept').includes('text/html')) {
            return await networkFirst(request);
        }
        
        // Default: network first
        return await networkFirst(request);
        
    } catch (error) {
        console.error('❌ Service Worker: Fetch error', error);
        
        // Fallback pentru HTML
        if (request.headers.get('accept').includes('text/html')) {
            return await caches.match('/') || new Response('Offline', { status: 503 });
        }
        
        // Fallback pentru alte resurse
        return new Response('Resource not available offline', { status: 503 });
    }
}

// Cache First Strategy - pentru fișiere statice
async function cacheFirst(request) {
    const cachedResponse = await caches.match(request);
    
    if (cachedResponse) {
        console.log('📦 Service Worker: Serving from cache', request.url);
        return cachedResponse;
    }
    
    try {
        const networkResponse = await fetch(request);
        
        if (networkResponse.ok) {
            const cache = await caches.open(STATIC_CACHE);
            cache.put(request, networkResponse.clone());
            console.log('💾 Service Worker: Cached new resource', request.url);
        }
        
        return networkResponse;
    } catch (error) {
        console.error('❌ Service Worker: Network failed for', request.url);
        throw error;
    }
}

// Network First Strategy - pentru API și HTML
async function networkFirst(request) {
    try {
        const networkResponse = await fetch(request);
        
        if (networkResponse.ok) {
            const cache = await caches.open(DYNAMIC_CACHE);
            cache.put(request, networkResponse.clone());
            console.log('🌐 Service Worker: Network response cached', request.url);
        }
        
        return networkResponse;
    } catch (error) {
        console.log('📦 Service Worker: Network failed, trying cache', request.url);
        
        const cachedResponse = await caches.match(request);
        
        if (cachedResponse) {
            console.log('✅ Service Worker: Serving from cache', request.url);
            return cachedResponse;
        }
        
        throw error;
    }
}

// Helper function pentru fișiere statice
function isStaticFile(pathname) {
    return pathname.match(/\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|ico)$/);
}

// Background sync pentru conversii
self.addEventListener('sync', event => {
    if (event.tag === 'background-conversion') {
        console.log('🔄 Service Worker: Background sync for conversion');
        event.waitUntil(handleBackgroundConversion());
    }
});

async function handleBackgroundConversion() {
    try {
        // Implementare pentru conversii în background
        console.log('🎵 Service Worker: Processing background conversion');
        
        // Aici poți implementa logica pentru conversii în background
        // De exemplu, să procesezi conversii care au eșuat
        
    } catch (error) {
        console.error('❌ Service Worker: Background sync failed', error);
    }
}

// Push notifications pentru status conversii
self.addEventListener('push', event => {
    console.log('📱 Service Worker: Push notification received');
    
    const options = {
        body: event.data ? event.data.text() : 'Conversia s-a terminat!',
        icon: '/static/images/icon-192.png',
        badge: '/static/images/badge-72.png',
        vibrate: [200, 100, 200],
        data: {
            dateOfArrival: Date.now(),
            primaryKey: 1
        },
        actions: [
            {
                action: 'open',
                title: 'Deschide aplicația',
                icon: '/static/images/checkmark.png'
            },
            {
                action: 'close',
                title: 'Închide',
                icon: '/static/images/xmark.png'
            }
        ]
    };
    
    event.waitUntil(
        self.registration.showNotification('Video Converter', options)
    );
});

// Notification click handler
self.addEventListener('notificationclick', event => {
    console.log('👆 Service Worker: Notification clicked');
    
    event.notification.close();
    
    if (event.action === 'open') {
        event.waitUntil(
            clients.openWindow('/')
        );
    }
});

// Message handler pentru comunicare cu aplicația
self.addEventListener('message', event => {
    console.log('💬 Service Worker: Message received', event.data);
    
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
    
    if (event.data && event.data.type === 'CACHE_CONVERSION') {
        // Cache conversia pentru acces offline
        event.waitUntil(cacheConversion(event.data.conversion));
    }
});

async function cacheConversion(conversion) {
    try {
        const cache = await caches.open(DYNAMIC_CACHE);
        const response = new Response(JSON.stringify(conversion), {
            headers: { 'Content-Type': 'application/json' }
        });
        
        await cache.put(`/api/conversion/${conversion.id}`, response);
        console.log('💾 Service Worker: Conversion cached', conversion.id);
    } catch (error) {
        console.error('❌ Service Worker: Failed to cache conversion', error);
    }
}

console.log('🎵 Video MP3 Converter Service Worker loaded successfully!');
