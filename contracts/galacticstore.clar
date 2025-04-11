;; GalacticStore - Advanced Digital Asset Storage Network

;; Main data structure for container management
(define-map ContainerRegistry
  { container-id: uint }
  {
    originator: principal,
    beneficiary: principal,
    asset-id: uint,
    quantity: uint,
    container-status: (string-ascii 10),
    activation-block: uint,
    expiration-block: uint
  }
)

;; Primary configuration constants
(define-constant NETWORK_CONTROLLER tx-sender)
(define-constant ERROR_ACCESS_DENIED (err u100))
(define-constant ERROR_CONTAINER_MISSING (err u101))
(define-constant ERROR_ALREADY_PROCESSED (err u102))
(define-constant ERROR_ASSET_MOVEMENT_FAILED (err u103))
(define-constant ERROR_INVALID_CONTAINER_ID (err u104))
(define-constant ERROR_INVALID_QUANTITY (err u105))
(define-constant ERROR_INVALID_ORIGINATOR (err u106))
(define-constant ERROR_CONTAINER_LAPSED (err u107))
(define-constant CONTAINER_LIFESPAN_BLOCKS u1008) 

;; Tracking the latest container ID
(define-data-var next-container-id uint u0)

;; Utility functions for validation

(define-private (valid-beneficiary? (beneficiary principal))
  (and 
    (not (is-eq beneficiary tx-sender))
    (not (is-eq beneficiary (as-contract tx-sender)))
  )
)

(define-private (valid-container-id? (container-id uint))
  (<= container-id (var-get next-container-id))
)

;; Core operational functions

;; Revert container assets to originator
(define-public (restore-container-assets (container-id uint))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (quantity (get quantity container-data))
      )
      (asserts! (is-eq tx-sender NETWORK_CONTROLLER) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get container-status container-data) "pending") ERROR_ALREADY_PROCESSED)
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set ContainerRegistry
              { container-id: container-id }
              (merge container-data { container-status: "reverted" })
            )
            (print {action: "assets_returned", container-id: container-id, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_ASSET_MOVEMENT_FAILED
      )
    )
  )
)

;; Originator initiates container reversal
(define-public (terminate-container (container-id uint))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (quantity (get quantity container-data))
      )
      (asserts! (is-eq tx-sender originator) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get container-status container-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get expiration-block container-data)) ERROR_CONTAINER_LAPSED)
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set ContainerRegistry
              { container-id: container-id }
              (merge container-data { container-status: "terminated" })
            )
            (print {action: "container_terminated", container-id: container-id, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_ASSET_MOVEMENT_FAILED
      )
    )
  )
)

;; Process successful container delivery to beneficiary
(define-public (finalize-container-transfer (container-id uint))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (beneficiary (get beneficiary container-data))
        (quantity (get quantity container-data))
        (asset (get asset-id container-data))
      )
      (asserts! (or (is-eq tx-sender NETWORK_CONTROLLER) (is-eq tx-sender (get originator container-data))) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get container-status container-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get expiration-block container-data)) ERROR_CONTAINER_LAPSED)
      (match (as-contract (stx-transfer? quantity tx-sender beneficiary))
        success
          (begin
            (map-set ContainerRegistry
              { container-id: container-id }
              (merge container-data { container-status: "completed" })
            )
            (print {action: "container_delivered", container-id: container-id, beneficiary: beneficiary, asset-id: asset, quantity: quantity})
            (ok true)
          )
        error ERROR_ASSET_MOVEMENT_FAILED
      )
    )
  )
)

;; Log formal objection to container status
(define-public (challenge-container (container-id uint) (justification (string-ascii 50)))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (beneficiary (get beneficiary container-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get container-status container-data) "pending") (is-eq (get container-status container-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get expiration-block container-data)) ERROR_CONTAINER_LAPSED)
      (map-set ContainerRegistry
        { container-id: container-id }
        (merge container-data { container-status: "challenged" })
      )
      (print {action: "container_challenged", container-id: container-id, challenger: tx-sender, justification: justification})
      (ok true)
    )
  )
)

;; Record cryptographic verification
(define-public (register-digital-signature (container-id uint) (signature (buff 65)))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (beneficiary (get beneficiary container-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get container-status container-data) "pending") (is-eq (get container-status container-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (print {action: "signature_recorded", container-id: container-id, signer: tx-sender, signature: signature})
      (ok true)
    )
  )
)

;; Register alternative recovery address
(define-public (register-recovery-address (container-id uint) (recovery-address principal))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
      )
      (asserts! (is-eq tx-sender originator) ERROR_ACCESS_DENIED)
      (asserts! (not (is-eq recovery-address tx-sender)) (err u111)) ;; Recovery address must be different
      (asserts! (is-eq (get container-status container-data) "pending") ERROR_ALREADY_PROCESSED)
      (print {action: "recovery_registered", container-id: container-id, originator: originator, recovery: recovery-address})
      (ok true)
    )
  )
)

;; Implement emergency protocol management for critical incidents
(define-public (activate-emergency-protocol (protocol-id (string-ascii 20)) (severity uint) (affected-containers (list 10 uint)))
  (begin
    (asserts! (or (is-eq tx-sender NETWORK_CONTROLLER)
                 (is-eq tx-sender (as-contract tx-sender))) ERROR_ACCESS_DENIED)
    (asserts! (> severity u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= severity u5) ERROR_INVALID_QUANTITY) ;; Scale 1-5
    (asserts! (> (len affected-containers) u0) (err u350)) ;; Must affect at least one container

    ;; Validate protocol type
    (asserts! (or (is-eq protocol-id "freeze-all")
                 (is-eq protocol-id "key-rotation-required")
                 (is-eq protocol-id "multi-sig-enforcement")
                 (is-eq protocol-id "proof-of-reserves")
                 (is-eq protocol-id "network-isolation")) (err u351))

    (let
      (
        (activation-block block-height)
        (protocol-duration (* u144 severity)) ;; Duration based on severity (in days)
        (affected-count (len affected-containers))
      )
      ;; In a full implementation, you would update protocol state in contract storage
      ;; Here we're logging the activation for demonstration

      ;; Update all affected containers to emergency state
      (map begin-emergency affected-containers)

      (print {action: "emergency_protocol_activated", protocol-id: protocol-id, 
              severity: severity, affected-count: affected-count,
              activation-block: activation-block, duration: protocol-duration,
              activated-by: tx-sender})

      (ok {
        protocol-id: protocol-id,
        activation-block: activation-block,
        duration: protocol-duration,
        affected-count: affected-count
      })
    )
  )
)

;; Helper function to process emergency state for a container
(define-private (begin-emergency (container-id uint))
  (match (map-get? ContainerRegistry { container-id: container-id })
    container-data
      (map-set ContainerRegistry
        { container-id: container-id }
        (merge container-data { container-status: "emergency" })
      )
    false
  )
)

;; Configure operation frequency limits
(define-public (configure-frequency-limits (max-attempts uint) (cooldown-period uint))
  (begin
    (asserts! (is-eq tx-sender NETWORK_CONTROLLER) ERROR_ACCESS_DENIED)
    (asserts! (> max-attempts u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= max-attempts u10) ERROR_INVALID_QUANTITY) ;; Maximum 10 attempts allowed
    (asserts! (> cooldown-period u6) ERROR_INVALID_QUANTITY) ;; Minimum 6 blocks cooldown (~1 hour)
    (asserts! (<= cooldown-period u144) ERROR_INVALID_QUANTITY) ;; Maximum 144 blocks cooldown (~1 day)

    ;; Note: Full implementation would track limits in contract variables

    (print {action: "frequency_limits_configured", max-attempts: max-attempts, 
            cooldown-period: cooldown-period, controller: tx-sender, current-block: block-height})
    (ok true)
  )
)

;; Increase container duration period
(define-public (prolong-container-lifespan (container-id uint) (additional-blocks uint))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (asserts! (> additional-blocks u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= additional-blocks u1440) ERROR_INVALID_QUANTITY) ;; Max ~10 days extension
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data)) 
        (beneficiary (get beneficiary container-data))
        (current-expiration (get expiration-block container-data))
        (new-expiration (+ current-expiration additional-blocks))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender NETWORK_CONTROLLER)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get container-status container-data) "pending") (is-eq (get container-status container-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (map-set ContainerRegistry
        { container-id: container-id }
        (merge container-data { expiration-block: new-expiration })
      )
      (print {action: "container_extended", container-id: container-id, requestor: tx-sender, new-expiration-block: new-expiration})
      (ok true)
    )
  )
)

;; Reclaim assets from expired containers
(define-public (retrieve-expired-container (container-id uint))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (quantity (get quantity container-data))
        (expiry (get expiration-block container-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender NETWORK_CONTROLLER)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get container-status container-data) "pending") (is-eq (get container-status container-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (> block-height expiry) (err u108)) ;; Must be expired
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set ContainerRegistry
              { container-id: container-id }
              (merge container-data { container-status: "expired" })
            )
            (print {action: "expired_container_retrieved", container-id: container-id, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_ASSET_MOVEMENT_FAILED
      )
    )
  )
)

;; Record supplementary container information
(define-public (record-container-metadata (container-id uint) (metadata-category (string-ascii 20)) (metadata-digest (buff 32)))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (beneficiary (get beneficiary container-data))
      )
      ;; Only authorized parties can add metadata
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender NETWORK_CONTROLLER)) ERROR_ACCESS_DENIED)
      (asserts! (not (is-eq (get container-status container-data) "completed")) (err u160))
      (asserts! (not (is-eq (get container-status container-data) "reverted")) (err u161))
      (asserts! (not (is-eq (get container-status container-data) "expired")) (err u162))

      ;; Valid metadata categories
      (asserts! (or (is-eq metadata-category "asset-details") 
                   (is-eq metadata-category "transfer-evidence")
                   (is-eq metadata-category "validation-report")
                   (is-eq metadata-category "originator-specs")) (err u163))

      (print {action: "metadata_recorded", container-id: container-id, metadata-category: metadata-category, 
              metadata-digest: metadata-digest, recorder: tx-sender})
      (ok true)
    )
  )
)

;; Mediate challenge with proportional allocation
(define-public (adjudicate-challenge (container-id uint) (originator-allocation uint))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (asserts! (is-eq tx-sender NETWORK_CONTROLLER) ERROR_ACCESS_DENIED)
    (asserts! (<= originator-allocation u100) ERROR_INVALID_QUANTITY) ;; Percentage must be 0-100
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (beneficiary (get beneficiary container-data))
        (quantity (get quantity container-data))
        (originator-share (/ (* quantity originator-allocation) u100))
        (beneficiary-share (- quantity originator-share))
      )
      (asserts! (is-eq (get container-status container-data) "challenged") (err u112)) ;; Must be challenged
      (asserts! (<= block-height (get expiration-block container-data)) ERROR_CONTAINER_LAPSED)

      ;; Transfer originator's portion
      (unwrap! (as-contract (stx-transfer? originator-share tx-sender originator)) ERROR_ASSET_MOVEMENT_FAILED)

      ;; Transfer beneficiary's portion
      (unwrap! (as-contract (stx-transfer? beneficiary-share tx-sender beneficiary)) ERROR_ASSET_MOVEMENT_FAILED)
      (print {action: "challenge_adjudicated", container-id: container-id, originator: originator, beneficiary: beneficiary, 
              originator-share: originator-share, beneficiary-share: beneficiary-share, originator-percentage: originator-allocation})
      (ok true)
    )
  )
)

;; Suspend container operations
(define-public (suspend-container-activity (container-id uint) (reason (string-ascii 100)))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (beneficiary (get beneficiary container-data))
      )
      (asserts! (or (is-eq tx-sender NETWORK_CONTROLLER) (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq (get container-status container-data) "pending") 
                   (is-eq (get container-status container-data) "accepted")) 
                ERROR_ALREADY_PROCESSED)
      (map-set ContainerRegistry
        { container-id: container-id }
        (merge container-data { container-status: "suspended" })
      )
      (print {action: "container_suspended", container-id: container-id, reporter: tx-sender, reason: reason})
      (ok true)
    )
  )
)

;; Create multi-phase asset delivery container
(define-public (create-phased-container (beneficiary principal) (asset-id uint) (quantity uint) (segments uint))
  (let 
    (
      (new-id (+ (var-get next-container-id) u1))
      (terminal-block (+ block-height CONTAINER_LIFESPAN_BLOCKS))
      (segment-quantity (/ quantity segments))
    )
    (asserts! (> quantity u0) ERROR_INVALID_QUANTITY)
    (asserts! (> segments u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= segments u5) ERROR_INVALID_QUANTITY) ;; Max 5 segments
    (asserts! (valid-beneficiary? beneficiary) ERROR_INVALID_ORIGINATOR)
    (asserts! (is-eq (* segment-quantity segments) quantity) (err u121)) ;; Ensure even division
    (match (stx-transfer? quantity tx-sender (as-contract tx-sender))
      success
        (begin
          (var-set next-container-id new-id)
          (print {action: "phased_container_created", container-id: new-id, originator: tx-sender, beneficiary: beneficiary, 
                  asset-id: asset-id, quantity: quantity, segments: segments, segment-quantity: segment-quantity})
          (ok new-id)
        )
      error ERROR_ASSET_MOVEMENT_FAILED
    )
  )
)

;; Register secondary authorization for high-value transactions
(define-public (register-secondary-authorization (container-id uint) (authorizer principal))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (quantity (get quantity container-data))
      )
      ;; Only for high-value containers (> 1000 STX)
      (asserts! (> quantity u1000) (err u120))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender NETWORK_CONTROLLER)) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get container-status container-data) "pending") ERROR_ALREADY_PROCESSED)
      (print {action: "authorization_registered", container-id: container-id, authorizer: authorizer, requestor: tx-sender})
      (ok true)
    )
  )
)

;; Schedule delayed critical operation
(define-public (schedule-protected-operation (operation-type (string-ascii 20)) (operation-params (list 10 uint)))
  (begin
    (asserts! (is-eq tx-sender NETWORK_CONTROLLER) ERROR_ACCESS_DENIED)
    (asserts! (> (len operation-params) u0) ERROR_INVALID_QUANTITY)
    (let
      (
        (scheduled-execution (+ block-height u144)) ;; 24 hours delay
      )
      (print {action: "operation_scheduled", operation-type: operation-type, operation-params: operation-params, scheduled-execution: scheduled-execution})
      (ok scheduled-execution)
    )
  )
)

;; Register enhanced security for high-value containers
(define-public (activate-enhanced-security (container-id uint) (security-code (buff 32)))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (quantity (get quantity container-data))
      )
      ;; Only for containers above threshold
      (asserts! (> quantity u5000) (err u130))
      (asserts! (is-eq tx-sender originator) ERROR_ACCESS_DENIED)
      (asserts! (is-eq (get container-status container-data) "pending") ERROR_ALREADY_PROCESSED)
      (print {action: "enhanced_security_activated", container-id: container-id, originator: originator, security-hash: (hash160 security-code)})
      (ok true)
    )
  )
)

;; Cryptographic verification for container operations
(define-public (validate-cryptographic-proof (container-id uint) (message-digest (buff 32)) (cryptographic-signature (buff 65)) (signatory principal))
  (begin
    (asserts! (valid-container-id? container-id) ERROR_INVALID_CONTAINER_ID)
    (let
      (
        (container-data (unwrap! (map-get? ContainerRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (beneficiary (get beneficiary container-data))
        (verification-result (unwrap! (secp256k1-recover? message-digest cryptographic-signature) (err u150)))
      )
      ;; Verify with cryptographic proof
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender NETWORK_CONTROLLER)) ERROR_ACCESS_DENIED)
      (asserts! (or (is-eq signatory originator) (is-eq signatory beneficiary)) (err u151))
      (asserts! (is-eq (get container-status container-data) "pending") ERROR_ALREADY_PROCESSED)

      ;; Verify signature matches expected signatory
      (asserts! (is-eq (unwrap! (principal-of? verification-result) (err u152)) signatory) (err u153))

      (print {action: "cryptographic_validation_complete", container-id: container-id, validator: tx-sender, signatory: signatory})
      (ok true)
    )
  )
)
