-------------------------------- MODULE Session --------------------------------
EXTENDS Naturals, FiniteSets, TLC

Versions == 1..3
LocalAllowed == {2, 3}
MaxMessages == 3
States == {"NEW", "NEGOTIATED", "PEER_AUTHENTICATED", "ARCHIVE_AUTHORIZED",
           "ACTIVE", "CLOSED", "FAILED"}

VARIABLES state, offered, selected, peerAuthenticated, archiveAuthorized,
          receiveSequence, replayAccepted, productMutation, authI2R, authR2I

vars == <<state, offered, selected, peerAuthenticated, archiveAuthorized,
          receiveSequence, replayAccepted, productMutation, authI2R, authR2I>>

Init ==
  /\ state = "NEW"
  /\ offered \in SUBSET Versions
  /\ selected = 0
  /\ peerAuthenticated = FALSE
  /\ archiveAuthorized = FALSE
  /\ receiveSequence = 0
  /\ replayAccepted = FALSE
  /\ productMutation = FALSE
  /\ authI2R = FALSE
  /\ authR2I = FALSE

Highest(S) == CHOOSE v \in S : \A w \in S : w <= v
Candidates == offered \cap LocalAllowed

Negotiate ==
  /\ state = "NEW"
  /\ Candidates # {}
  /\ state' = "NEGOTIATED"
  /\ selected' = Highest(Candidates)
  /\ UNCHANGED <<offered, peerAuthenticated, archiveAuthorized,
                  receiveSequence, replayAccepted, productMutation,
                  authI2R, authR2I>>

NoCommonVersion ==
  /\ state = "NEW"
  /\ Candidates = {}
  /\ state' = "FAILED"
  /\ UNCHANGED <<offered, selected, peerAuthenticated, archiveAuthorized,
                  receiveSequence, replayAccepted, productMutation,
                  authI2R, authR2I>>

\* Mutual peer-auth: both directions required before PEER_AUTHENTICATED.
AuthenticateI2R ==
  /\ state = "NEGOTIATED"
  /\ ~authI2R
  /\ selected = Highest(Candidates)
  /\ authI2R' = TRUE
  /\ IF authR2I
     THEN /\ state' = "PEER_AUTHENTICATED"
          /\ peerAuthenticated' = TRUE
     ELSE UNCHANGED <<state, peerAuthenticated>>
  /\ UNCHANGED <<offered, selected, archiveAuthorized, receiveSequence,
                  replayAccepted, productMutation, authR2I>>

AuthenticateR2I ==
  /\ state = "NEGOTIATED"
  /\ ~authR2I
  /\ selected = Highest(Candidates)
  /\ authR2I' = TRUE
  /\ IF authI2R
     THEN /\ state' = "PEER_AUTHENTICATED"
          /\ peerAuthenticated' = TRUE
     ELSE UNCHANGED <<state, peerAuthenticated>>
  /\ UNCHANGED <<offered, selected, archiveAuthorized, receiveSequence,
                  replayAccepted, productMutation, authI2R>>

AuthorizeArchive ==
  /\ state = "PEER_AUTHENTICATED"
  /\ peerAuthenticated
  /\ state' = "ARCHIVE_AUTHORIZED"
  /\ archiveAuthorized' = TRUE
  /\ UNCHANGED <<offered, selected, peerAuthenticated, receiveSequence,
                  replayAccepted, productMutation, authI2R, authR2I>>

Activate ==
  /\ state = "ARCHIVE_AUTHORIZED"
  /\ peerAuthenticated /\ archiveAuthorized
  /\ selected = Highest(Candidates)
  /\ state' = "ACTIVE"
  /\ UNCHANGED <<offered, selected, peerAuthenticated, archiveAuthorized,
                  receiveSequence, replayAccepted, productMutation,
                  authI2R, authR2I>>

AcceptNext ==
  /\ state = "ACTIVE"
  /\ receiveSequence < MaxMessages
  /\ receiveSequence' = receiveSequence + 1
  /\ productMutation' = TRUE
  /\ UNCHANGED <<state, offered, selected, peerAuthenticated,
                  archiveAuthorized, replayAccepted, authI2R, authR2I>>

RejectReplay ==
  /\ state = "ACTIVE"
  /\ state' = "FAILED"
  /\ replayAccepted' = FALSE
  /\ UNCHANGED <<offered, selected, peerAuthenticated, archiveAuthorized,
                  receiveSequence, productMutation, authI2R, authR2I>>

Close ==
  /\ state = "ACTIVE"
  /\ state' = "CLOSED"
  /\ UNCHANGED <<offered, selected, peerAuthenticated, archiveAuthorized,
                  receiveSequence, replayAccepted, productMutation,
                  authI2R, authR2I>>

Next == Negotiate \/ NoCommonVersion \/ AuthenticateI2R \/ AuthenticateR2I \/
        AuthorizeArchive \/ Activate \/ AcceptNext \/ RejectReplay \/ Close

TypeOK ==
  /\ state \in States
  /\ offered \subseteq Versions
  /\ selected \in 0..3
  /\ peerAuthenticated \in BOOLEAN
  /\ archiveAuthorized \in BOOLEAN
  /\ receiveSequence \in 0..MaxMessages
  /\ replayAccepted \in BOOLEAN
  /\ productMutation \in BOOLEAN
  /\ authI2R \in BOOLEAN
  /\ authR2I \in BOOLEAN

ActiveIsAuthorized == state = "ACTIVE" => (peerAuthenticated /\ archiveAuthorized)
ActiveIsNotDowngraded == state = "ACTIVE" => selected = Highest(Candidates)
ReplayNeverAccepted == ~replayAccepted
MutationIsAuthorized == productMutation => (peerAuthenticated /\ archiveAuthorized)
PeerAuthIsMutual ==
  state = "PEER_AUTHENTICATED" => (authI2R /\ authR2I)

Spec == Init /\ [][Next]_vars

=============================================================================
