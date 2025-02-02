namespace ElectionGuard.Core;

public class GuardianKeys
{
    public required GuardianIndex Index { get; init; }
    public required List<KeyPair> VoteEncryptionKeyPairs { get; init; }
    public required List<KeyPair> OtherBallotDataEncryptionKeyPairs { get; init; }
    public required KeyPair CommunicationKeyPair { get; init; }
    public required Proof VoteEncryptionKeyProof { get; init; }
    public required Proof OtherBallotDataEncryptionKeyProof { get; init; }

    public GuardianPublicView ToPublicView()
    {
        return new GuardianPublicView
        {
            Index = Index,
            VoteEncryptionCommitments = VoteEncryptionKeyPairs.Select(k => k.PublicKey).ToList(),
            OtherBallotDataEncryptionCommitments = OtherBallotDataEncryptionKeyPairs.Select(k => k.PublicKey).ToList(),
            CommunicationPublicKey = CommunicationKeyPair.PublicKey,
            VoteEncryptionProof = VoteEncryptionKeyProof,
            OtherDataEncryptionProof = OtherBallotDataEncryptionKeyProof,
        };
    }
}
