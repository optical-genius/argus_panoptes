import { DlpScanResult } from '../scanner/types';

type VisualTokenResolver = (category: string, opaqueToken: string) => string;
const opaqueTokenPattern = /^<ARGUS_([A-Z][A-Z0-9_]*)_([0-9a-f]{32})>$/;
const opaqueTokenPatternGlobal = /<ARGUS_([A-Z][A-Z0-9_]*)_([0-9a-f]{32})>/g;
const truncatedOpaqueTokenPattern = /<ARGUS_([A-Z][A-Z0-9_]*)_([0-9a-f]{0,32})\.\.\.$/;

function createVisualTokenResolver(): VisualTokenResolver {
  const aliases = new Map<string, string>();
  const counters = new Map<string, number>();

  return (category: string, opaqueToken: string): string => {
    const existingAlias = aliases.get(opaqueToken);
    if (existingAlias) {
      return existingAlias;
    }

    const nextNumber = (counters.get(category) || 0) + 1;
    const visualAlias = `<ARGUS_${category}_${nextNumber}>`;
    counters.set(category, nextNumber);
    aliases.set(opaqueToken, visualAlias);
    return visualAlias;
  };
}

export function replaceOpaqueTokensForDisplay(text: string, resolveToken: VisualTokenResolver): string {
  const displayedText = text.replace(opaqueTokenPatternGlobal, (opaqueToken, category) =>
    resolveToken(category, opaqueToken)
  );

  const truncatedTokenMatch = displayedText.match(truncatedOpaqueTokenPattern);
  if (!truncatedTokenMatch) {
    return displayedText;
  }

  const truncatedToken = truncatedTokenMatch[0];
  const visualAlias = resolveToken(
    truncatedTokenMatch[1],
    `truncated:${truncatedToken}`
  );
  return displayedText.slice(0, -truncatedToken.length) + visualAlias + '...';
}

export function createVisualScanResult(result: DlpScanResult): DlpScanResult {
  const resolveToken = createVisualTokenResolver();
  const entities = result.entities.map(entity => ({
    ...entity,
    matchedText: '',
    redactedPlaceholder: opaqueTokenPattern.test(entity.redactedPlaceholder) &&
      entity.redactedPlaceholder.startsWith(`<ARGUS_${entity.category}_`)
      ? resolveToken(entity.category, entity.redactedPlaceholder)
      : entity.redactedPlaceholder
  }));

  return {
    ...result,
    entities,
    sanitizedText: replaceOpaqueTokensForDisplay(result.sanitizedText, resolveToken)
  };
}

export function getVisualPromptSnippet(promptSnippet: string): string {
  return replaceOpaqueTokensForDisplay(promptSnippet, createVisualTokenResolver());
}
