-------------------------------- MODULE Session --------------------------------
EXTENDS Naturals, FiniteSets, TLC

Versions == 1..3
LocalAllowed == {2, 3}
MaxMessages == 3
States == {"NEW", "NEGOTIATED", "PEER_AUTHENTICATED", "ARCHIVE_AUTHORIZED",
           "ACTIVE", "CLOSED", "FAILED"}

VARIABLES state, offered, selected, peerAuthenticated, archiveAuthorized,
          receiveSequence, replayAccepted, productMutation

vars == <<state, offered, selected, peerAuthenticated, archiveAuthorized,
          receiveSequence, replayAccepted, productMutation>>

Init ==
  /\ state = "NEW"
  /\ offered \in SUBSET Versions
  /\ selected = 0
  /\ peerAuthenticated = FALSE
  /\ archiveAuthorized = FALSE
  /\ receiveSequence = 0
  /\ replayAccepted = FALSE
  /\ productMutation = FALSE

Highest(S) == CHOOSE v \in S : \A w \in S : w <= v
Candidates == offered \cap LocalAllowed

Negotiate ==
  /\ state = "NEW"
  /\ Candidates # {}
  /\ state' = "NEGOTIATED"
  /\ selected' = Highest(Candidates)
  /\ UNCHANGED <<offered, peerAuthenticated, archiveAuthorized,
                  receiveSequence, replayAccepted, productMutation>>

NoCommonVersion ==
  /\ state = "NEW"
  /\ Candidates = {}
  /\ state' = "FAILED"
  /\ UNCHANGED <<offered, selected, peerAuthenticated, archiveAuthorized,
                  receiveSequence, replayAccepted, productMutation>>

Authenticate ==
  /\ state = "NEGOTIATED"
  /\ selected = Highest(Candidates)
  /\ state' = "PEER_AUTHENTICATED"
  /\ peerAuthenticated' = TRUE
  /\ UNCHANGED <<offered, selected, archiveAuthorized, receiveSequence,
                  replayAccepted, productMutation>>

AuthorizeArchive ==
  /\ state = "PEER_AUTHENTICATED"
  /\ peerAuthenticated
  /\ state' = "ARCHIVE_AUTHORIZED"
  /\ archiveAuthorized' = TRUE
  /\ UNCHANGED <<offered, selected, peerAuthenticated, receiveSequence,
                  replayAccepted, productMutation>>

Activate ==
  /\ state = "ARCHIVE_AUTHORIZED"
  /\ peerAuthenticated /\ archiveAuthorized
  /\ selected = Highest(Candidates)
  /\ state' = "ACTIVE"
  /\ UNCHANGED <<offered, selected, peerAuthenticated, archiveAuthorized,
                  receiveSequence, replayAccepted, productMutation>>

AcceptNext ==
  /\ state = "ACTIVE"
  /\ receiveSequence < MaxMessages
  /\ receiveSequence' = receiveSequence + 1
  /\ productMutation' = TRUE
  /\ UNCHANGED <<state, offered, selected, peerAuthenticated,
                  archiveAuthorized, replayAccepted>>

RejectReplay ==
  /\ state = "ACTIVE"
  /\ state' = "FAILED"
  /\ replayAccepted' = FALSE
  /\ UNCHANGED <<offered, selected, peerAuthenticated, archiveAuthorized,
                  receiveSequence, productMutation>>

Close ==
  /\ state = "ACTIVE"
  /\ state' = "CLOSED"
  /\ UNCHANGED <<offered, selected, peerAuthenticated, archiveAuthorized,
                  receiveSequence, replayAccepted, productMutation>>

Next == Negotiate \/ NoCommonVersion \/ Authenticate \/ AuthorizeArchive \/
        Activate \/ AcceptNext \/ RejectReplay \/ Close

TypeOK ==
  /\ state \in States
  /\ offered \subseteq Versions
  /\ selected \in 0..3
  /\ peerAuthenticated \in BOOLEAN
  /\ archiveAuthorized \in BOOLEAN
  /\ receiveSequence \in 0..MaxMessages
  /\ replayAccepted \in BOOLEAN
  /\ productMutation \in BOOLEAN

ActiveIsAuthorized == state = "ACTIVE" => (peerAuthenticated /\ archiveAuthorized)
ActiveIsNotDowngraded == state = "ACTIVE" => selected = Highest(Candidates)
ReplayNeverAccepted == ~replayAccepted
MutationIsAuthorized == productMutation => (peerAuthenticated /\ archiveAuthorized)

Spec == Init /\ [][Next]_vars

=============================================================================
