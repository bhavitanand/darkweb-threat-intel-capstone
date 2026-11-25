import type { ReactNode } from 'react';
import { useSession } from '../session';
import { SignInForm } from '../pages/SignIn';
import { ErrorBox, Loading, PageHead } from './ui';

/** Pages that belong to a person (My alerts, Set alerts, Connectors, Workspace) ask for sign-in first. */
export default function Gate({ title, why, children }: { title: string; why: string; children: ReactNode }) {
  const s = useSession();
  if (!s.signedIn) {
    return (
      <>
        <PageHead title={title} sub={why} />
        <div style={{ maxWidth: 460 }}>
          <SignInForm note="Sign in to use this page. It takes one email and no password." />
        </div>
      </>
    );
  }
  if (s.error && !s.ws) return <ErrorBox message={s.error} />;
  if (!s.ws) return <Loading what="your workspace" />;
  return <>{children}</>;
}
