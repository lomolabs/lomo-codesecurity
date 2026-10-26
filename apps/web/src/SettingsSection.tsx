import type { ReactNode } from 'react';

export function SettingsSection({ id, title, description, children }: {
  id: string;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <section className="settings-section" id={id} aria-labelledby={`${id}-title`}>
      <header className="settings-section-heading">
        <h2 id={`${id}-title`}>{title}</h2>
        <p>{description}</p>
      </header>
      <div className="settings-section-content">{children}</div>
    </section>
  );
}
