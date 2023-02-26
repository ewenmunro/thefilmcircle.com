import { auth } from "../libraries/firebase";

// sign out button
function SignOutButton() {
  return (
    <button className="btn-container" onClick={() => auth.signOut()}>
      Sign Out
    </button>
  );
}

export default function UserProfile() {
  const user = auth.currentUser;

  return (
    <div className="box-center">
      {user ? (
        <>
          <img src={user.photoURL} className="card-img-center" />
          <h1>{user.displayName}</h1>
          <SignOutButton />
        </>
      ) : (
        <p>Sign in to view this user's profile</p>
      )}
    </div>
  );
}
