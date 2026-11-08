// Array Escape (repro) — landing page that leaks the signing secret to the client.
import { SIGNING_SECRET } from "./api/token";

export async function getServerSideProps() {
  // EXPECT: line 6 secret-in-props CWE-200 signing secret shipped in page props
  return { props: { signingSecret: SIGNING_SECRET, build: "2026.1" } };
}

export default function Home({ signingSecret, build }) {
  // The secret is now serialised into the HTML sent to every visitor.
  return (
    <main>
      <h1>Docs Portal</h1>
      <p>Build {build}</p>
      <span data-k={signingSecret} />
    </main>
  );
}
