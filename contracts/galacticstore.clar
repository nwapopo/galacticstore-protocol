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
