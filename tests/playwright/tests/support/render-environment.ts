import { Page } from '@playwright/test';

const selectors = ['h1', 'nav button', '.workbench-summary dd', '.finding-evidence .code-source'];

/** Diagnostics for the generated fixture page only. Never persists text, field
 * values, storage, cookies or the browser's full command line. */
export async function captureRenderEnvironment(page: Page) {
  const document = await page.evaluate((targets) => ({
    devicePixelRatio,
    userAgent: navigator.userAgent,
    focused: window.document.hasFocus(),
    visibility: window.document.visibilityState,
    fontsStatus: window.document.fonts.status,
    viewport: { width: innerWidth, height: innerHeight, scale: visualViewport?.scale },
    window: { width: outerWidth, height: outerHeight, x: screenX, y: screenY },
    screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth },
    elements: targets.map((selector) => {
      const element = window.document.querySelector(selector);
      if (!element) return { selector, present: false };
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return {
        selector, present: true,
        rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
        fontFamily: style.fontFamily, fontSize: style.fontSize, fontWeight: style.fontWeight,
        lineHeight: style.lineHeight, letterSpacing: style.letterSpacing,
        fontOpticalSizing: style.fontOpticalSizing, fontVariationSettings: style.fontVariationSettings,
        textRendering: style.textRendering,
      };
    }),
  }), selectors);
  const session = await page.context().newCDPSession(page);
  try {
    await session.send('DOM.enable');
    await session.send('CSS.enable');
    const { root } = await session.send('DOM.getDocument', { depth: 0 });
    const platformFonts = [];
    for (const selector of selectors) {
      const { nodeId } = await session.send('DOM.querySelector', { nodeId: root.nodeId, selector });
      if (!nodeId) { platformFonts.push({ selector, present: false }); continue; }
      const { fonts } = await session.send('CSS.getPlatformFontsForNode', { nodeId });
      if (fonts.length > 20) throw new Error('Render diagnostics exceeded the font inventory bound.');
      platformFonts.push({ selector, present: true, fonts: fonts.map(font => ({
        familyName: font.familyName, postScriptName: font.postScriptName,
        isCustomFont: font.isCustomFont, glyphCount: font.glyphCount,
      })) });
    }
    let renderingArguments: { status: 'available' | 'unavailable'; values: string[]; reason?: string };
    try {
      const { arguments: args } = await session.send('Browser.getBrowserCommandLine');
      renderingArguments = {
        status: 'available',
        values: args.filter(arg => /^--(?:headless(?:=\w+)?|disable-gpu|force-device-scale-factor=[\d.]+|force-color-profile=[\w-]+|use-angle=[\w-]+)$/.test(arg)),
      };
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes('because --enable-automation not set')) throw error;
      renderingArguments = { status: 'unavailable', values: [], reason: 'Browser did not enable launch-argument inspection.' };
    }
    const { bounds } = await session.send('Browser.getWindowForTarget');
    return {
      schema: 'lomo-fixture-render-environment/v1',
      observedAt: new Date().toISOString(),
      browserVersion: page.context().browser()?.version(),
      document, platformFonts, browserWindowBounds: bounds,
      renderingArguments,
    };
  } finally {
    await session.detach();
  }
}
