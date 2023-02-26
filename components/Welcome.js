import { auth } from "../libraries/firebase";

export default function Welcome() {
  const user = auth.currentUser;

  return (
    <div className="box-center">
      <>
        <h1>Welcome {user.displayName}!</h1>
        <p>Here is a quick rundown for how to use this website:</p>
        <p>
          - <i>The Film Circle</i> logo is the Home page where you can view job
          posts. Click on any job post to view the job and apply to it.
        </p>
        <p>
          - 'My Job Posts' is where you can create a job post of your own and
          view previous job posts you have created.
        </p>
        <p>
          - Your Profile Photo is your personal profile and is where you can
          sign out of your account.
        </p>
      </>
    </div>
  );
}
