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

