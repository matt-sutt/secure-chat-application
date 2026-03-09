import os
import re
import sqlite3
import hashlib
import secrets
import logging
import time
from datetime import datetime, timezone
import uuid
from socp.modularImp.our_crytography import Cryptography
from socp.modularImp.logging_config import setup_logging

# logging
setup_logging() 
logger = logging.getLogger("Database")
logger.disabled = True 
logging.disable(logging.NOTSET)

# silence the following logs
logging.getLogger("asyncio").disabled = True
logging.getLogger("websockets").disabled = True
logging.getLogger("websockets.client").disabled = True
logging.getLogger("websockets.server").disabled = True
logging.getLogger("Database").disabled = True


class DatabaseManager:  # handles sqlite storage
    def __init__(self, db_path: str = "mychat.db"):  # constructor
        self.db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_path)  # resolve db path
        logger.debug("[DB] init: db_path=%s", self.db_path)
        self.init_database()  # ensure schema exists
        self.crypto = Cryptography()  # crypto helper
        logger.debug("[DB] ready")

    def _get_db(self):  # open connection
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # rows as dict-like
        logger.debug("[DB] open sqlite connection → %s", self.db_path)
        return conn

    def init_database(self):  # create tables if missing
        logger.debug("[DB] ensuring schema exists (users)")
        with self._get_db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    pubkey_b64 TEXT NOT NULL,
                    privkey_store_b64 BLOB NOT NULL,
                    password TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.commit()
        logger.debug("[DB] schema OK")

    # Registration / Authentication
    def register_user(self, username: str, password: str):  # add new user
        logger.debug("[DB] register attempt username=%s password=%s", username, password)

        if not username or not password:  # require both fields
            logger.warning("[DB] register failed: missing username/password username=%s", username)
            return {"ok": False, "error": "username and password required"}

        valid, reasons = self._validate_password_verbose(password)  # check password policy
        if not valid:  # reject weak password
            logger.warning("[DB] register failed: password policy username=%s reasons=%s", username, reasons)
            return {"Register_Status": "You need at least 8 characters, mixed up with capital letters"}

        try:
            user_id = str(uuid.uuid4())  # generate user id
            private_key, public_key = self.crypto.generate_rsa_keys()  # make rsa keypair
            pubkey_b64 = self.crypto.export_public_key_b64url(public_key)  # encode public key
            priv_blob = self.crypto.export_private_key_pem(private_key, password)  # encrypt private key

            hashed_pw, meta = self._hash_password_verbose(password)  # hash password

            with self._get_db() as conn:  # write user row
                conn.execute(
                    """
                    INSERT INTO users (user_id, username, pubkey_b64, privkey_store_b64, password, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, username, pubkey_b64, priv_blob, hashed_pw, datetime.now(timezone.utc).isoformat()),
                )

            logger.debug("[DB] register success user_id=%s username=%s hash_meta=%s", user_id, username, meta)
            return {"Register_Status": True, "msg": "user registered"}  # registration ok

        except sqlite3.IntegrityError:  # username taken
            logger.warning("[DB] register failed: duplicate username=%s", username)
            return {"Register_Status": False, "error": "username already exists"}
        except Exception as e:  # unexpected error
            logger.error("[DB] register failed username=%s error=%s", username, e, exc_info=True)
            return {"Register_Status": False, "error": "internal_error"}

    def authenticate_user(self, username: str, password: str):  # verify credentials
        logger.debug("[DB] login attempt username=%s password=%s", username, password)

        try:
            with self._get_db() as conn:
                row = conn.execute(  # fetch user row
                    "SELECT user_id, username, password, created_at FROM users WHERE username = ?",
                    (username,),
                ).fetchone()

            if not row:  # unknown user
                logger.warning("[DB] login failed: unknown username=%s", username)
                return {"Login_Status": False, "error": "invalid username or password"}

            stored = row["password"]  # stored hash
            ok, vmeta = self._verify_password_verbose(password, stored)  # check password

            if ok:  # login ok
                logger.debug("[DB] login success username=%s verify_meta=%s", username, vmeta)
                return {"Login_Status": True, "msg": "login successful"}

            logger.warning("[DB] login failed: bad password username=%s verify_meta=%s", username, vmeta)  # bad password
            return {"Login_Status": False, "error": "invalid username or password"}

        except Exception as e:  # unexpected error
            logger.error("[DB] login failed username=%s error=%s", username, e, exc_info=True)
            return {"Login_Status": False, "error": "internal_error"}

    # Password ops (verbose, no masking)
    def hash_password(self, password: str) -> str:  # simple hash wrapper
        hashed, _ = self._hash_password_verbose(password)
        return hashed

    def _hash_password_verbose(self, password: str):  # hash with pbkdf2
        iters = 200_000  # iterations count
        salt = secrets.token_bytes(16)  # random salt
        t0 = time.perf_counter()  # timing start
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)  # derive key
        dt_ms = (time.perf_counter() - t0) * 1000.0  # elapsed ms
        stored = f"{salt.hex()}:{dk.hex()}"  # store salt and hash

        logger.debug(
            "[DB] PBKDF2 hash: pw='%s' len=%d iters=%d salt_len=%d dk_len=%d time_ms=%.2f "
            "salt_hex=%s dk_hex=%s stored='%s'",
            password, len(password), iters, len(salt), len(dk), dt_ms,
            salt.hex(), dk.hex(), stored
        )

        meta = {  # debug info
            "iters": iters,
            "salt_len": len(salt),
            "dk_len": len(dk),
            "time_ms": round(dt_ms, 2),
        }
        return stored, meta

    def verify_password(self, password: str, stored: str) -> bool:  # simple verify wrapper
        ok, _ = self._verify_password_verbose(password, stored)
        return ok

    def _verify_password_verbose(self, password: str, stored: str):  # verify pbkdf2 hash
        iters = 200_000
        try:
            salt_hex, hash_hex = stored.split(":", 1)  # decode stored hash
            salt = bytes.fromhex(salt_hex)  # salt bytes
            expected = bytes.fromhex(hash_hex)  # expected bytes

            t0 = time.perf_counter()  # timing start
            test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)  # derive for compare
            ok = secrets.compare_digest(test, expected)  # constant time compare
            dt_ms = (time.perf_counter() - t0) * 1000.0  # elapsed ms

            logger.debug(
                "[DB] PBKDF2 verify: pw='%s' len=%d iters=%d time_ms=%.2f match=%s "
                "salt_hex=%s expected_hex=%s test_hex=%s stored='%s'",
                password, len(password), iters, dt_ms, ok,
                salt_hex, hash_hex, test.hex(), stored
            )

            vmeta = {  # debug info
                "iters": iters,
                "salt_len": len(salt),
                "dk_len": len(test),
                "time_ms": round(dt_ms, 2),
                "match": ok,
            }
            return ok, vmeta

        except Exception as e:  # verification error
            logger.error("[DB] password verification error pw='%s' stored='%s' error=%s",
                         password, stored, e, exc_info=True)
            return False, {"error": str(e)}

    def validate_password(self, password: str) -> bool:  # simple policy wrapper
        ok, _ = self._validate_password_verbose(password)
        return ok

    def _validate_password_verbose(self, password: str):  # enforce password policy
        reasons = []  # collect reasons
        if password is None:  # handle none
            reasons.append("none")
            result = False
        else:
            if len(password) < 8:
                reasons.append("len<8")
            if not re.search(r"[A-Z]", password):
                reasons.append("no-uppercase")
            if not re.search(r"[a-z]", password):
                reasons.append("no-lowercase")
            if not re.search(r"[0-9]", password):
                reasons.append("no-digit")
            result = len(reasons) == 0  # valid if no reasons

        logger.debug("[DB] password validate: pw='%s' len=%s => %s reasons=%s",
                     password, len(password) if password else 0, result, reasons or "[]")
        return result, reasons

    # Profiles
    def get_user_full_by_username(self, username: str):  # full user profile
        """
        Return full profile, including privkey_store (bytes).
        Use base64 when you serialize to JSON.
        """
        with self._get_db() as conn:  # open db
            row = conn.execute(
                """
                SELECT user_id, username, pubkey_b64, privkey_store_b64, created_at
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
            if not row:  # not found
                return None
            return {  # return fields
                "user_id": row["user_id"],
                "username": row["username"],
                "pubkey_b64": row["pubkey_b64"],
                # keep raw bytes here, server will base64 this before sending
                "privkey_store_b64": row["privkey_store_b64"],
                "created_at": row["created_at"],
            }

    def get_user_full_by_id(self, user_id: str):  # full profile by id
        with self._get_db() as conn:
            row = conn.execute(
                """
                SELECT user_id, username, pubkey_b64, privkey_store_b64, created_at
                FROM users
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            if not row:
                return None
            return {
                "user_id": row["user_id"],
                "username": row["username"],
                "pubkey_b64": row["pubkey_b64"],
                "privkey_store_b64": row["privkey_store_b64"],
                "created_at": row["created_at"],
            }