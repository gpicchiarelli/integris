------------------------------ MODULE Transaction ------------------------------
EXTENDS Naturals, TLC

States == {
  "CREATED", "AUTHENTICATED", "MANIFEST_VERIFIED", "PLANNED", "AUTHORIZED",
  "CONTENT_RECEIVED", "PREPARED", "VERIFIED", "PUBLISHING", "PUBLISHED",
  "CONFIRMED", "SUSPENDED", "CANCELLED", "QUARANTINED", "RECOVERING",
  "IRRECOVERABLE"
}

VARIABLES state, authorized, contentReceived, prepared, contentVerified,
          publicationStarted, published, confirmationCount, recoveryCount

vars == <<state, authorized, contentReceived, prepared, contentVerified,
          publicationStarted, published, confirmationCount, recoveryCount>>

Init ==
  /\ state = "CREATED"
  /\ authorized = FALSE
  /\ contentReceived = FALSE
  /\ prepared = FALSE
  /\ contentVerified = FALSE
  /\ publicationStarted = FALSE
  /\ published = FALSE
  /\ confirmationCount = 0
  /\ recoveryCount = 0

Step(from, to) ==
  /\ state = from
  /\ state' = to
  /\ UNCHANGED <<authorized, contentReceived, prepared, contentVerified,
                  publicationStarted, published, confirmationCount, recoveryCount>>

Authorize ==
  /\ state = "PLANNED"
  /\ state' = "AUTHORIZED"
  /\ authorized' = TRUE
  /\ UNCHANGED <<contentReceived, prepared, contentVerified, publicationStarted,
                  published, confirmationCount, recoveryCount>>

Receive ==
  /\ state = "AUTHORIZED"
  /\ authorized
  /\ state' = "CONTENT_RECEIVED"
  /\ contentReceived' = TRUE
  /\ UNCHANGED <<authorized, prepared, contentVerified, publicationStarted,
                  published, confirmationCount, recoveryCount>>

Prepare ==
  /\ state = "CONTENT_RECEIVED"
  /\ authorized /\ contentReceived
  /\ state' = "PREPARED"
  /\ prepared' = TRUE
  /\ UNCHANGED <<authorized, contentReceived, contentVerified,
                  publicationStarted, published, confirmationCount, recoveryCount>>

Verify ==
  /\ state = "PREPARED"
  /\ authorized /\ contentReceived /\ prepared
  /\ state' = "VERIFIED"
  /\ contentVerified' = TRUE
  /\ UNCHANGED <<authorized, contentReceived, prepared, publicationStarted,
                  published, confirmationCount, recoveryCount>>

BeginPublication ==
  /\ state = "VERIFIED"
  /\ authorized /\ contentReceived /\ prepared /\ contentVerified
  /\ state' = "PUBLISHING"
  /\ publicationStarted' = TRUE
  /\ UNCHANGED <<authorized, contentReceived, prepared, contentVerified,
                  published, confirmationCount, recoveryCount>>

CompletePublication ==
  /\ state = "PUBLISHING"
  /\ publicationStarted /\ authorized /\ prepared /\ contentVerified
  /\ state' = "PUBLISHED"
  /\ published' = TRUE
  /\ UNCHANGED <<authorized, contentReceived, prepared, contentVerified,
                  publicationStarted, confirmationCount, recoveryCount>>

Confirm ==
  /\ state = "PUBLISHED"
  /\ published
  /\ confirmationCount = 0
  /\ state' = "CONFIRMED"
  /\ confirmationCount' = 1
  /\ UNCHANGED <<authorized, contentReceived, prepared, contentVerified,
                  publicationStarted, published, recoveryCount>>

Crash ==
  /\ state \in {"AUTHORIZED", "CONTENT_RECEIVED", "PREPARED", "VERIFIED",
                  "PUBLISHING", "PUBLISHED"}
  /\ recoveryCount = 0
  /\ state' = "RECOVERING"
  /\ UNCHANGED <<authorized, contentReceived, prepared, contentVerified,
                  publicationStarted, published, confirmationCount, recoveryCount>>

Recover ==
  /\ state = "RECOVERING"
  /\ state' = IF published THEN "PUBLISHED" ELSE "QUARANTINED"
  /\ recoveryCount' = 1
  /\ UNCHANGED <<authorized, contentReceived, prepared, contentVerified,
                  publicationStarted, published, confirmationCount>>

RecoverAgain ==
  /\ recoveryCount > 0
  /\ state \in {"PUBLISHED", "QUARANTINED"}
  /\ UNCHANGED vars

Cancel ==
  /\ state \in {"CREATED", "AUTHENTICATED", "MANIFEST_VERIFIED", "PLANNED",
                  "AUTHORIZED", "CONTENT_RECEIVED", "PREPARED", "VERIFIED"}
  /\ ~publicationStarted
  /\ state' = "CANCELLED"
  /\ UNCHANGED <<authorized, contentReceived, prepared, contentVerified,
                  publicationStarted, published, confirmationCount, recoveryCount>>

Next ==
  \/ Step("CREATED", "AUTHENTICATED")
  \/ Step("AUTHENTICATED", "MANIFEST_VERIFIED")
  \/ Step("MANIFEST_VERIFIED", "PLANNED")
  \/ Authorize \/ Receive \/ Prepare \/ Verify
  \/ BeginPublication \/ CompletePublication \/ Confirm
  \/ Crash \/ Recover \/ RecoverAgain \/ Cancel

TypeOK ==
  /\ state \in States
  /\ authorized \in BOOLEAN
  /\ contentReceived \in BOOLEAN
  /\ prepared \in BOOLEAN
  /\ contentVerified \in BOOLEAN
  /\ publicationStarted \in BOOLEAN
  /\ published \in BOOLEAN
  /\ confirmationCount \in 0..1
  /\ recoveryCount \in 0..1

PublicationAuthorized == published => authorized
PublicationPrepared == published => (contentReceived /\ prepared /\ contentVerified)
ConfirmationSound == (confirmationCount = 1) => published
ConfirmationUnique == confirmationCount <= 1
NoInventedPublication == (~publicationStarted) => (~published)

Spec == Init /\ [][Next]_vars

=============================================================================
