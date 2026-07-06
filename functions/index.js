const {onCall, HttpsError} = require("firebase-functions/v2/https");
const {onSchedule} = require("firebase-functions/v2/scheduler");
const admin = require("firebase-admin");
const {v1} = require("@google-cloud/firestore");

admin.initializeApp();
const db = admin.firestore();

const PROJECT_ID = "mishmarot-2506e";
const BACKUP_BUCKET = "gs://mishmarot-2506e-backup";

// ============================================================
// verifyEmployeeLogin
// ------------------------------------------------------------
// Server-side "reception desk" for employee login.
//
// The client sends a businessCode + personalCode (exactly what the
// employee types into login.html today). This function verifies both
// against Firestore using the Admin SDK (which is trusted and bypasses
// security rules - that's expected and safe, because this code runs on
// Google's servers, not in the visitor's browser).
//
// If valid, it mints a Firebase Auth custom token carrying a custom claim
// "businessId" tied to that specific business. The client then signs in
// with that token (signInWithCustomToken), giving the employee session a
// real, verifiable identity that Firestore security rules can check -
// instead of an anonymous session that has no link to any business.
// ============================================================
exports.verifyEmployeeLogin = onCall(async (request) => {
  const businessCode = (request.data && request.data.businessCode || "").trim();
  const personalCode = (request.data && request.data.personalCode || "").trim();

  if (!businessCode || !personalCode) {
    throw new HttpsError("invalid-argument", "נא למלא קוד עסק וקוד אישי");
  }

  // 1. Find the business by its 4-digit code.
  const bizSnap = await db.collection("businesses")
      .where("businessCode", "==", businessCode)
      .limit(1)
      .get();

  if (bizSnap.empty) {
    throw new HttpsError("not-found", "קוד עסק לא נמצא");
  }

  const businessDoc = bizSnap.docs[0];
  const businessId = businessDoc.id;
  const businessData = businessDoc.data();

  if (businessData.active === false || businessData.archived) {
    throw new HttpsError("permission-denied", "עסק לא פעיל");
  }

  // 2. Find the employee by personal code, within that business only.
  const empSnap = await db.collection("businesses").doc(businessId)
      .collection("employees")
      .where("code", "==", personalCode)
      .limit(1)
      .get();

  if (empSnap.empty) {
    throw new HttpsError("not-found", "קוד אישי לא נמצא");
  }

  const empDoc = empSnap.docs[0];
  const empData = empDoc.data();

  if (empData.archived) {
    throw new HttpsError("permission-denied", "עובד לא פעיל");
  }

  // 3. Mint a scoped custom token. The synthetic uid is namespaced so it
  // can never collide with a manager's real Firebase Auth uid.
  const uid = "emp_" + businessId + "_" + empDoc.id;
  const customToken = await admin.auth().createCustomToken(uid, {
    businessId: businessId,
    employeeId: empDoc.id,
    role: "employee",
  });

  return {
    token: customToken,
    businessId: businessId,
    businessData: businessData,
    employee: {id: empDoc.id, ...empData},
  };
});

// ============================================================
// scheduledFirestoreBackup
// ------------------------------------------------------------
// Runs automatically every day at 03:00 Israel time. Exports the entire
// Firestore database to Cloud Storage - exactly like the manual
// "gcloud firestore export" command, just automatic.
//
// Each day gets its own dated folder (auto-backup-YYYY-MM-DD), so old
// backups are never overwritten or deleted by this function.
// ============================================================
const firestoreAdminClient = new v1.FirestoreAdminClient();

exports.scheduledFirestoreBackup = onSchedule(
    {
      schedule: "0 3 * * *",
      timeZone: "Asia/Jerusalem",
      retryCount: 2,
    },
    async (event) => {
      const today = new Date().toISOString().slice(0, 10);
      const databaseName =
        firestoreAdminClient.databasePath(PROJECT_ID, "(default)");

      await firestoreAdminClient.exportDocuments({
        name: databaseName,
        outputUriPrefix: `${BACKUP_BUCKET}/auto-backup-${today}`,
        collectionIds: [], // empty = export all collections
      });

      console.log(`Scheduled Firestore backup started for ${today}`);
    },
);
