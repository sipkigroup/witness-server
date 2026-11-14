// What the timestamps prove, by organisation profile (ARHITEKTURA-0.2 7). smb: "independent timestamps" up front,
// Bitcoin only under "More -> internal guarantee"; enterprise: both anchors named.
export function anchorText(profile) {
  if (profile === 'enterprise') {
    return {
      lead: 'Two kinds of anchors fix the time of your ledger every hour: Bitcoin (OpenTimestamps) and an RFC 3161 timestamp authority.',
      more: [
        'Bitcoin: the hourly Merkle root is committed to the Bitcoin blockchain through OpenTimestamps. Nobody needs to be trusted, but confirmation takes hours.',
        'RFC 3161: the same root is stamped by a timestamp authority whose terms allow it (FreeTSA today). It is a trusted third party and not a qualified (eIDAS) timestamp; the token and its certificate chain are in the evidence pack and verify offline.',
        'Two different grounds: the authority and Bitcoin. To backdate an entry, both would have to be wrong. Bitcoin fixes the time to within hours ("not later than block N").',
      ],
      moreTitle: 'Details',
    };
  }
  return {
    lead: 'Independent timestamps: every hour your ledger is stamped outside Deus Witness, so entries cannot be backdated without it showing.',
    more: [
      'Internal guarantee: the same hourly root is also committed to the Bitcoin blockchain (OpenTimestamps). You do not need to do anything with it; the evidence pack checker verifies it offline.',
    ],
    moreTitle: 'More',
  };
}
