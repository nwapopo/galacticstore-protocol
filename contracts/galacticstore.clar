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

