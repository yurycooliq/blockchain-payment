// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4 <0.9.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title Accept payments in ERC20 tokens for any order in your store.
 * @author Yuri Cooliq <yuricooliq@gmail.com>.
 * @notice This contract designed to accept ERC20 payments for any order.
 * @dev How to use:
 * 1. Customer creating an order (backend should store it in DB with unique orderId)
 * 2. Backend generates a signature (see examples folder)
 * 3. Backend send signature to the frontend
 * 4. Customer accept token spending for this contract
 * 5. Customer execute transaction
 * 6. Backend listening for OrderPaid event with orderId
 * 7. After catching event, change order status to "paid by customer"
 * @custom:version 1.0.
 */
contract AcceptERC20ForAnyOrder is Ownable {
    /// @dev SafeERC20 library from OpenZeppelin.
    using SafeERC20 for IERC20;

    /// @dev For validator recovering.
    using ECDSA for bytes32;

    /// @notice Address of merchant. Can be a simple wallet (EOA), multi-sig or contract.
    address public recipient;

    /// @notice Signer EOA on the backend side.
    address public signer;

    /// @notice Is this contract is active?
    bool public enabled = true;

    /// @notice Is payments from the other wallets is allowed?
    bool public isPayFromEnabled;

    /**
     * @notice Order is paid by customer.
     * @param buyer Customer address.
     * @param orderId Unique string to identify order on the backend side.
     * @param coin Address of the coin, used by the customer to pay for the order (limit on the backend side).
     * @param amount Amount of the coin.
     */
    event OrderPaid(
        address indexed buyer,
        string indexed orderId,
        address coin,
        uint256 amount
    );

    /**
     * @notice Merchant wallet changed.
     * @param oldRecipient Old wallet.
     * @param newRecipient New wallet.
     */
    event RecipientChanged(address oldRecipient, address newRecipient);

    /**
     * @notice Backend signer address is changed.
     * @param oldSigner Old signer address.
     * @param newSigner New signer address.
     */
    event SignerChanged(address oldSigner, address newSigner);

    /**
     * @notice Contract status changed.
     * @param status Is contract is enabled?
     */
    event StatusChanged(bool status);

    /**
     * @notice Function payFrom enabled or disabled.
     * @param status Is payFrom is enabled?
     */
    event StatusForThePayFromChanged(bool status);

    /// @notice Address can't be 0x0000000000000000000000000000000000000000.
    error ZeroAddress();

    /// @notice Contract is disabled and didn't accept any payments.
    error ContractDisabled();

    /// @notice Unknown signer or bad signature.
    error BadSignature();

    /// @notice Buyer should be a transaction sender.
    error BuyerIsNotASender();

    /**
     * Executes ones on deployment.
     * @param _recipient Merchant address.
     * @param _signer Signature generator address.
     */
    constructor(address _recipient, address _signer) {
        if (_recipient == address(0) || _signer == address(0))
            revert ZeroAddress();
        (recipient, signer) = (_recipient, _signer);
    }

    /**
     * @notice Pay for order.
     * @param coin Token (limit acceptable coins on the backend side).
     * @param amount Amount of tokens (get amount from the backend side).
     * @param orderId ID of the order to recognize customer on the merchant's backend.
     * @param signature For validation incoming data.
     */
    function pay(
        address coin,
        uint256 amount,
        string memory orderId,
        bytes memory signature
    ) external {
        _pay(msg.sender, coin, amount, orderId, signature);
    }

    /**
     * @notice Pay for order from the other address.
     * @dev Allow customer to pay from the other account.
     * @param buyer Customer's account.
     * @param coin Token (limit acceptable coins on the backend side).
     * @param amount Amount of tokens (get amount from the backend side).
     * @param orderId ID of the order to recognize customer on the merchant's backend.
     * @param signature For validation incoming data.
     */
    function payFrom(
        address buyer,
        address coin,
        uint256 amount,
        string memory orderId,
        bytes memory signature
    ) external {
        if (!isPayFromEnabled) revert BuyerIsNotASender();
        _pay(buyer, coin, amount, orderId, signature);
    }

    /**
     * @notice Change merchant's address.
     * @dev Only owner of the contract can call this function.
     * @param newReceiver New merchants address.
     */
    function changeReceiver(address newReceiver) external onlyOwner {
        if (newReceiver == address(0)) revert ZeroAddress();
        emit RecipientChanged(recipient, newReceiver);
        recipient = newReceiver;
    }

    /**
     * @notice Change backend validator.
     * @dev Only owner of the contract can call this function.
     * @param newSigner Change validator's address.
     */
    function changeSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ZeroAddress();
        emit SignerChanged(signer, newSigner);
        signer = newSigner;
    }

    /**
     * @notice Enable or disable contract.
     * @dev Only owner of the contract can call this function.
     */
    function switchStatus() external onlyOwner {
        enabled = !enabled;
        emit StatusChanged(enabled);
    }

    /**
     * @notice Enable or disable payments from the differet wallets.
     * @dev Only owner of the contract can call this function.
     */
    function switchPayFromAllowance() external onlyOwner {
        isPayFromEnabled = !isPayFromEnabled;
        emit StatusForThePayFromChanged(isPayFromEnabled);
    }

    /**
     * @notice Proceed payment.
     * @param buyer Customer's address.
     * @param coin Token (limit acceptable coins on the backend side).
     * @param amount Amount of tokens (get amount from the backend side).
     * @param orderId ID of the order to recognize customer on the merchant's backend.
     * @param signature For validation incoming data.
     */
    function _pay(
        address buyer,
        address coin,
        uint256 amount,
        string memory orderId,
        bytes memory signature
    ) internal {
        // Check is this contract is allowed to proceed customer payments
        if (!enabled) revert ContractDisabled();
        // Hash data
        bytes32 msgHash = keccak256(abi.encode(buyer, coin, amount, orderId));
        // Signature verification
        if (
            msgHash.toEthSignedMessageHash().recover(signature) != signer
        ) revert BadSignature();
        // Transfer tokens from customer to merchant
        IERC20(coin).safeTransferFrom(msg.sender, recipient, amount);
        // Customer paid his order
        emit OrderPaid(buyer, orderId, coin, amount);
    }
}
