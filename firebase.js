// ============================================
// firebase.js - v4 - Complete Module
// ============================================

import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js';
import {
    getAuth,
    createUserWithEmailAndPassword as _createUser,
    signInWithEmailAndPassword     as _signIn,
    signOut                        as _signOut,
    sendEmailVerification          as _sendVerification,
    sendPasswordResetEmail         as _sendReset,
    onAuthStateChanged             as _onAuthStateChanged,
    fetchSignInMethodsForEmail     as _fetchSignInMethods,
} from 'https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js';
import {
    getFirestore,
    doc         as _doc,
    setDoc      as _setDoc,
    getDoc      as _getDoc,
    getDocs     as _getDocs,
    updateDoc   as _updateDoc,
    deleteDoc   as _deleteDoc,
    collection  as _collection,
    query       as _query,
    where       as _where,
    orderBy     as _orderBy,
    limit       as _limit,
    serverTimestamp as _serverTimestamp,
    Timestamp   as _Timestamp,
    onSnapshot  as _onSnapshot,
    writeBatch  as _writeBatch,
    arrayUnion  as _arrayUnion,
    arrayRemove as _arrayRemove,
} from 'https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js';

// ════════════════════════════════════════════
// CONFIG - Update WORKER_BASE_URL to your worker URL
// ════════════════════════════════════════════
const WORKER_BASE_URL = 'https://dashverse-api-proxy.thondaladinne-masthan.workers.dev';
const MAX_RETRIES     = 3;
const FETCH_TIMEOUT   = 12000;

// ════════════════════════════════════════════
// Internal state
// ════════════════════════════════════════════
let _app               = null;
let _authInstance      = null;
let _dbInstance        = null;
let _firebaseConfig    = null;
let _initialized       = false;
let _initPromise       = null;
let _initError         = null;
let _authListenerQueue = [];

// ════════════════════════════════════════════
// Fetch with timeout helper
// ════════════════════════════════════════════
async function fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(timeoutId);
        return response;
    } catch (e) {
        clearTimeout(timeoutId);
        if (e.name === 'AbortError') {
            throw new Error(`Request timed out after ${timeoutMs}ms: ${url}`);
        }
        throw e;
    }
}

// ════════════════════════════════════════════
// Initialize Firebase (with retry)
// ════════════════════════════════════════════
async function _doInit() {
    if (_initialized) return;

    console.log('🔄 Fetching Firebase config...');

    let lastError = null;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        try {
            if (attempt > 1) {
                const delay = Math.min(1000 * Math.pow(2, attempt - 2), 4000);
                console.log(`⏳ Retry ${attempt}/${MAX_RETRIES} in ${delay}ms...`);
                await new Promise(r => setTimeout(r, delay));
            }

            const response = await fetchWithTimeout(
                `${WORKER_BASE_URL}/api/config`,
                {
                    method:  'GET',
                    headers: {
                        'Accept':           'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                        'X-App-Origin':     window.location.origin,
                    },
                    credentials: 'omit',
                },
                FETCH_TIMEOUT
            );

            if (!response.ok) {
                let errorBody = '';
                try { errorBody = await response.text(); } catch (_) {}
                throw new Error(`HTTP ${response.status}: ${errorBody.substring(0, 300)}`);
            }

            let config;
            try {
                config = await response.json();
            } catch (parseErr) {
                throw new Error(`Failed to parse config JSON: ${parseErr.message}`);
            }

            const missing = [];
            if (!config.apiKey)     missing.push('apiKey');
            if (!config.authDomain) missing.push('authDomain');
            if (!config.projectId)  missing.push('projectId');

            if (missing.length > 0) {
                throw new Error(`Incomplete config, missing: ${missing.join(', ')}`);
            }

            _firebaseConfig = config;
            _app            = initializeApp(config);
            _authInstance   = getAuth(_app);
            _dbInstance     = getFirestore(_app);

            _initialized = true;
            _initError   = null;
            console.log('✅ Firebase ready!');

            if (_authListenerQueue.length > 0) {
                _authListenerQueue.forEach(({ callback, resolveUnsub }) => {
                    const unsub = _onAuthStateChanged(_authInstance, callback);
                    resolveUnsub(unsub);
                });
                _authListenerQueue = [];
            }

            return;

        } catch (err) {
            lastError = err;
            console.error(`❌ Attempt ${attempt} failed:`, err.message);

            const isNetworkError = (
                err.message.includes('timed out') ||
                err.message.includes('Failed to fetch') ||
                err.message.includes('NetworkError') ||
                err.message.includes('fetch')
            );
            if (!isNetworkError && attempt === 1) break;
        }
    }

    _initError = lastError;
    _authListenerQueue.forEach(({ callback }) => {
        try { callback(null); } catch (e) {}
    });
    _authListenerQueue = [];
    throw lastError;
}

function ensureInitialized() {
    if (!_initPromise) {
        _initPromise = _doInit();
    }
    return _initPromise;
}

ensureInitialized().catch(err => {
    console.error('🔴 Background Firebase init failed:', err.message);
});

// ════════════════════════════════════════════
// Auth proxy
// ════════════════════════════════════════════
const auth = new Proxy({}, {
    get(target, prop) {
        if (prop === 'currentUser') return _authInstance?.currentUser ?? null;
        if (prop === 'signOut')     return () => _authInstance?.signOut() ?? Promise.resolve();
        if (prop === 'app')         return _authInstance?.app ?? null;
        if (prop === 'name')        return _authInstance?.name ?? '[DEFAULT]';
        if (prop === 'config')      return _authInstance?.config ?? {};
        if (_authInstance && prop in _authInstance) {
            const val = _authInstance[prop];
            return typeof val === 'function' ? val.bind(_authInstance) : val;
        }
        return undefined;
    },
});

// ════════════════════════════════════════════
// Firestore proxy
// ════════════════════════════════════════════
const db = new Proxy({}, {
    get(target, prop) {
        if (!_dbInstance) {
            if (prop === 'type')   return 'firestore';
            if (prop === 'app')    return null;
            if (prop === 'toJSON') return () => ({});
            return undefined;
        }
        const val = _dbInstance[prop];
        return typeof val === 'function' ? val.bind(_dbInstance) : val;
    },
});

// ════════════════════════════════════════════
// Firestore helpers
// ════════════════════════════════════════════
function _resolveDb(ref) {
    if (ref === db) {
        if (!_dbInstance) throw new Error('Firestore not initialized yet');
        return _dbInstance;
    }
    return ref;
}

function doc(dbRef, ...args)        { return _doc(_resolveDb(dbRef), ...args); }
function collection(dbRef, ...args) { return _collection(_resolveDb(dbRef), ...args); }
function writeBatch(dbRef)          { return _writeBatch(_resolveDb(dbRef)); }
function setDoc(...args)            { return _setDoc(...args); }
function getDoc(...args)            { return _getDoc(...args); }
function getDocs(...args)           { return _getDocs(...args); }
function updateDoc(...args)         { return _updateDoc(...args); }
function deleteDoc(...args)         { return _deleteDoc(...args); }
function query(...args)             { return _query(...args); }
function where(...args)             { return _where(...args); }
function orderBy(...args)           { return _orderBy(...args); }
function limit(...args)             { return _limit(...args); }
function onSnapshot(...args)        { return _onSnapshot(...args); }
function serverTimestamp()          { return _serverTimestamp(); }
function arrayUnion(...args)        { return _arrayUnion(...args); }
function arrayRemove(...args)       { return _arrayRemove(...args); }
const Timestamp = _Timestamp;

// ════════════════════════════════════════════
// Auth helpers
// ════════════════════════════════════════════
function onAuthStateChanged(authRefOrCb, maybeCb) {
    const cb = typeof authRefOrCb === 'function' ? authRefOrCb : maybeCb;

    if (!cb || typeof cb !== 'function') {
        console.error('onAuthStateChanged: callback must be a function');
        return () => {};
    }

    if (_initialized && _authInstance) {
        return _onAuthStateChanged(_authInstance, cb);
    }

    if (_initError) {
        try { cb(null); } catch (e) {}
        return () => {};
    }

    let unsubscribe = null;
    let cancelled   = false;

    const entry = {
        callback:     cb,
        resolveUnsub: (unsub) => {
            if (cancelled) { try { unsub(); } catch (e) {} }
            else            { unsubscribe = unsub; }
        },
    };

    _authListenerQueue.push(entry);
    ensureInitialized().catch(() => {});

    return () => {
        cancelled = true;
        if (unsubscribe) { try { unsubscribe(); } catch (e) {} }
        const idx = _authListenerQueue.indexOf(entry);
        if (idx !== -1) _authListenerQueue.splice(idx, 1);
    };
}

async function signInWithEmailAndPassword(authRef, email, password) {
    await ensureInitialized();
    const e = String(email    || '').trim().toLowerCase().substring(0, 254);
    const p = String(password || '').substring(0, 128);
    return _signIn(_authInstance, e, p);
}

async function createUserWithEmailAndPassword(authRef, email, password) {
    await ensureInitialized();
    const e = String(email    || '').trim().toLowerCase().substring(0, 254);
    const p = String(password || '').substring(0, 128);
    return _createUser(_authInstance, e, p);
}

async function signOut(authRef) {
    await ensureInitialized();
    return _signOut(_authInstance);
}

async function sendEmailVerification(user) {
    await ensureInitialized();
    return _sendVerification(user);
}

async function sendPasswordResetEmail(authRef, email) {
    await ensureInitialized();
    const e = String(email || '').trim().toLowerCase().substring(0, 254);
    return _sendReset(_authInstance, e);
}

async function fetchSignInMethodsForEmail(authRef, email) {
    await ensureInitialized();
    const e = String(email || '').trim().toLowerCase().substring(0, 254);
    return _fetchSignInMethods(_authInstance, e);
}

async function getIdToken(forceRefresh = false) {
    await ensureInitialized();
    const user = _authInstance?.currentUser;
    if (!user) throw new Error('No authenticated user');
    try {
        return await user.getIdToken(forceRefresh);
    } catch (e) {
        if (!forceRefresh && e.code === 'auth/id-token-expired') {
            return await user.getIdToken(true);
        }
        throw e;
    }
}

// ════════════════════════════════════════════
// Writer Change History Helpers
// ════════════════════════════════════════════
function buildWriterChangeEntry(fromWriter, toWriter, reason, adminEmail) {
    return {
        reason:     String(reason      || '').trim().substring(0, 500),
        changedAt:  new Date().toISOString(),
        changedBy:  String(adminEmail  || '').substring(0, 254),
        fromWriter: String(fromWriter  || '').trim().substring(0, 100),
        toWriter:   String(toWriter    || '').trim().substring(0, 100),
        seenAt:     null,
        seenBy:     null,
    };
}

function markHistoryAsSeen(history, adminEmail) {
    if (!Array.isArray(history)) return [];
    const now = new Date().toISOString();
    return history.map(entry =>
        entry.seenAt ? entry : {
            ...entry,
            seenAt: now,
            seenBy: String(adminEmail || '').substring(0, 254),
        }
    );
}

function hasUnseenWriterChange(show) {
    if (!show) return false;
    const history = Array.isArray(show.writerChangeHistory) ? show.writerChangeHistory : [];
    if (history.some(e => !e.seenAt)) return true;
    if (show.writerChangeReason && !show.writerChangeSeenAt) return true;
    return false;
}

function getWriterChangeHistory(show) {
    if (!show) return [];
    const history = Array.isArray(show.writerChangeHistory) ? show.writerChangeHistory : [];
    if (history.length === 0 && show.writerChangeReason) {
        return [{
            reason:     show.writerChangeReason,
            changedAt:  show.writerChangeReasonAt || '',
            changedBy:  show.writerChangeReasonBy || '',
            fromWriter: '',
            toWriter:   show.assignedTo || '',
            seenAt:     show.writerChangeSeenAt || null,
            seenBy:     null,
        }];
    }
    return history;
}

// ════════════════════════════════════════════
// Security Utilities
// ════════════════════════════════════════════
function sanitizeHTML(str) {
    if (str == null) return '';
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(String(str)));
    return d.innerHTML;
}

function isValidURL(str) {
    if (!str || typeof str !== 'string') return true;
    const trimmed = str.trim();
    if (!trimmed) return true;
    try {
        const url      = new URL(trimmed);
        if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
        const hostname = url.hostname.toLowerCase();
        if (
            hostname === 'localhost'         ||
            hostname === '127.0.0.1'         ||
            hostname.startsWith('192.168.')  ||
            hostname.startsWith('10.')       ||
            hostname.startsWith('172.16.')
        ) return false;
        return true;
    } catch {
        return false;
    }
}

function isValidEmail(email) {
    if (!email) return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function truncate(str, maxLen = 500) {
    if (!str) return '';
    const s = String(str).trim();
    return s.length > maxLen ? s.substring(0, maxLen) : s;
}

class RateLimiter {
    constructor(maxActions, windowMs) {
        this.maxActions = maxActions;
        this.windowMs   = windowMs;
        this.actions    = [];
    }
    canProceed() {
        const now    = Date.now();
        this.actions = this.actions.filter(t => now - t < this.windowMs);
        if (this.actions.length >= this.maxActions) return false;
        this.actions.push(now);
        return true;
    }
    getWaitTime() {
        if (this.actions.length < this.maxActions) return 0;
        return Math.max(0, this.windowMs - (Date.now() - this.actions[0]));
    }
    reset() { this.actions = []; }
}

const SecureSession = {
    setUserData(data) {
        try {
            const sanitized = {
                uid:   String(data.uid   || '').substring(0, 128),
                name:  String(data.name  || '').substring(0, 100),
                email: String(data.email || '').substring(0, 254),
                role:  ['admin', 'writer'].includes(data.role) ? data.role : 'writer',
            };
            sessionStorage.setItem('_dv_user', JSON.stringify({
                data:      sanitized,
                timestamp: Date.now(),
                checksum:  this._checksum(JSON.stringify(sanitized)),
            }));
        } catch (e) {
            console.error('Session write error:', e);
        }
    },
    getUserData() {
        try {
            const raw = sessionStorage.getItem('_dv_user');
            if (!raw) return null;
            const payload = JSON.parse(raw);
            if (!payload?.data || !payload.timestamp || !payload.checksum) {
                this.clear(); return null;
            }
            if (payload.checksum !== this._checksum(JSON.stringify(payload.data))) {
                this.clear(); return null;
            }
            if (Date.now() - payload.timestamp > 8 * 60 * 60 * 1000) {
                this.clear(); return null;
            }
            return payload.data;
        } catch (e) {
            this.clear(); return null;
        }
    },
    setPendingVerification(data) {
        try {
            sessionStorage.setItem('_dv_pending', JSON.stringify({
                email: String(data.email || '').substring(0, 254),
                name:  String(data.name  || '').substring(0, 100),
            }));
        } catch (e) {}
    },
    getPendingVerification() {
        try {
            const raw = sessionStorage.getItem('_dv_pending');
            return raw ? JSON.parse(raw) : null;
        } catch (e) { return null; }
    },
    clear() {
        try {
            ['_dv_user', '_dv_pending', 'userData', 'pendingVerification']
                .forEach(k => sessionStorage.removeItem(k));
        } catch (e) {}
    },
    _checksum(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash = hash & hash;
        }
        return 'cs_' + Math.abs(hash).toString(36);
    },
};

// ════════════════════════════════════════════
// Exports
// ════════════════════════════════════════════
const WORKER_URL = WORKER_BASE_URL;

export {
    auth, db, ensureInitialized, WORKER_URL,

    // Auth
    onAuthStateChanged, signInWithEmailAndPassword,
    createUserWithEmailAndPassword, signOut,
    sendEmailVerification, sendPasswordResetEmail,
    fetchSignInMethodsForEmail,

    // Firestore
    doc, setDoc, getDoc, getDocs, updateDoc, deleteDoc,
    collection, query, where, orderBy, limit,
    onSnapshot, writeBatch, serverTimestamp,
    Timestamp, arrayUnion, arrayRemove,

    // Writer history
    buildWriterChangeEntry, markHistoryAsSeen,
    hasUnseenWriterChange, getWriterChangeHistory,

    // Utils
    getIdToken, sanitizeHTML, isValidURL, isValidEmail,
    truncate, RateLimiter, SecureSession,
};