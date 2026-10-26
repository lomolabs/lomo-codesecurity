/** Off-route collections keep their last observation until their next entry.
 * Initial loads, explicit refreshes, mutations and background reconciliation
 * still read everything. Navigation never renews an off-route observation.
 */
export function navigationRefreshCollections(view: string) {
  return {
    summary: view === 'overview',
    projects: view !== 'settings',
    scans: view !== 'settings',
    jobs: view === 'jobs' || view === 'tools',
    tools: view === 'tools',
    lifecycle: view === 'tools',
    preflight: view === 'projects' || view === 'tools',
    sourceBoundary: view === 'projects',
  };
}
