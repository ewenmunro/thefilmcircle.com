"use strict";
exports.id = 52;
exports.ids = [52];
exports.modules = {

/***/ 2052:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Bt": () => (/* binding */ serverTimestamp),
/* harmony export */   "I8": () => (/* binding */ auth),
/* harmony export */   "Lg": () => (/* binding */ fromMillis),
/* harmony export */   "Lp": () => (/* binding */ getUserWithUsername),
/* harmony export */   "RZ": () => (/* binding */ firestore),
/* harmony export */   "WS": () => (/* binding */ postToJSON),
/* harmony export */   "mC": () => (/* binding */ STATE_CHANGED),
/* harmony export */   "qV": () => (/* binding */ googleAuthProvider),
/* harmony export */   "tO": () => (/* binding */ storage)
/* harmony export */ });
/* harmony import */ var firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3773);
/* harmony import */ var firebase_compat_auth__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(4826);
/* harmony import */ var firebase_compat_firestore__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(741);
/* harmony import */ var firebase_compat_storage__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(451);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__, firebase_compat_auth__WEBPACK_IMPORTED_MODULE_1__, firebase_compat_firestore__WEBPACK_IMPORTED_MODULE_2__, firebase_compat_storage__WEBPACK_IMPORTED_MODULE_3__]);
([firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__, firebase_compat_auth__WEBPACK_IMPORTED_MODULE_1__, firebase_compat_firestore__WEBPACK_IMPORTED_MODULE_2__, firebase_compat_storage__WEBPACK_IMPORTED_MODULE_3__] = __webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__);




const firebaseConfig = {
    apiKey: "AIzaSyCD4CqdGD5u7p1O_mMkmBeLrS9EtrWv3Mo",
    authDomain: "the-film-circle-d4cf1.firebaseapp.com",
    projectId: "the-film-circle-d4cf1",
    storageBucket: "the-film-circle-d4cf1.appspot.com",
    messagingSenderId: "333168772321",
    appId: "1:333168772321:web:27fcbb58aa8b53d1a6a3a0",
    measurementId: "G-6HX1MC68WR"
};
if (!firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].apps.length) {
    firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].initializeApp(firebaseConfig);
}
const auth = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].auth();
const googleAuthProvider = new firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].auth.GoogleAuthProvider();
const firestore = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore();
const storage = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].storage();
const fromMillis = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore.Timestamp.fromMillis;
const serverTimestamp = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore.FieldValue.serverTimestamp;
const STATE_CHANGED = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].storage.TaskEvent.STATE_CHANGED;
async function getUserWithUsername(username) {
    const usersRef = firestore.collection("users");
    const query = usersRef.where("username", "==", username).limit(1);
    const userDoc = (await query.get()).docs[0];
    return userDoc;
}
function postToJSON(doc) {
    const data = doc.data();
    return {
        ...data,
        createdAt: data.createdAt.toMillis(),
        updatedAt: data.updatedAt.toMillis()
    };
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ })

};
;