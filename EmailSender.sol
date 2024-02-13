// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import '@openzeppelin/contracts/access/AccessControl.sol';
import '@openzeppelin/contracts/security/ReentrancyGuard.sol';
import '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import '@openzeppelin/contracts/utils/math/SafeMath.sol';

contract EmailSender is AccessControl, ReentrancyGuard {
  using SafeERC20 for IERC20;
  using SafeMath for uint;

  bytes32 public constant ADMIN_ROLE = keccak256('ADMIN_ROLE');
  bytes32 public constant MODERATOR_ROLE = keccak256('MODERATOR_ROLE');

  string public constant name = 'EmailSender';

  uint256 public referralPercent;
  uint256 public percent;
  address payable public bank;

  mapping(address => string) private walletToEmail;
  mapping(string => address) private emailToWallet;
  mapping(string => address) private emailToReferral;
  mapping(string => mapping(address => uint256)) private emailDeposits;
  mapping(string => address[]) private emailTokens;
  mapping(string => mapping(address => uint256)) private emailDepositTimestamps;

  uint256 public constant UNCLAIMED_DURATION = 365 days; // Example: 1 year

  event WalletLinked(bytes32 email, address wallet, address referral);
  event PaymentProcessed(bytes32 email, address wallet, address token, uint256 amount);
  event TokensSent(bytes32 email, address token, uint256 amount);
  event TokensReclaimed(bytes32 email, address token, uint256 amount);
  event ModeratorAdded(address moderator);
  event ModeratorRemoved(address moderator);

  constructor(address _admin, address _moderator, address _bank) {
    require(_admin != address(0), 'Admin address is not set');
    require(_bank != address(0), 'Bank address cannot be zero');

    _setupRole(ADMIN_ROLE, _admin);
    _setupRole(MODERATOR_ROLE, _moderator);

    referralPercent = 5; // 0.1%
    percent = 10; // 0.1%
    bank = payable(_bank);
  }

  modifier onlyModeratorAndOwner() {
    require(
      hasRole(MODERATOR_ROLE, msg.sender) || hasRole(ADMIN_ROLE, msg.sender),
      'Caller is not a moderator'
    );
    _;
  }

  function addModerator(address _moderator) public onlyRole(ADMIN_ROLE) {
    grantRole(MODERATOR_ROLE, _moderator);
    emit ModeratorAdded(_moderator);
  }

  function removeModerator(address _moderator) public onlyRole(ADMIN_ROLE) {
    revokeRole(MODERATOR_ROLE, _moderator);
    emit ModeratorRemoved(_moderator);
  }

  function changePercentage(uint256 _percent) public onlyRole(ADMIN_ROLE) {
    require(_percent < 10000, 'Bigger than amount');
    percent = _percent;
  }

  function changeReferralPercentage(uint256 _percent) public onlyRole(ADMIN_ROLE) {
    require(_percent < percent, 'Bigger than fee amount');
    referralPercent = _percent;
  }

  function changeBankAddress(address _bank) public onlyRole(ADMIN_ROLE) {
    require(_bank != address(0), 'Bank address cannot be zero');
    bank = payable(_bank);
  }

  function linkWallets(
    string[] memory emails,
    address[] memory wallets,
    address[] memory referrals
  ) public onlyModeratorAndOwner nonReentrant payable {
    require(emails.length > 0, 'emails list is empty');
    require(emails.length == wallets.length, 'Lengths of emails and wallets arrays do not match');
    require(
      wallets.length == referrals.length,
      'Lengths of wallets and referrals arrays do not match'
    );

    for (uint256 i = 0; i < emails.length; i++) {
      require(wallets[i] != address(0), 'Wallet address cannot be zero');
      emailToWallet[emails[i]] = wallets[i];
      walletToEmail[wallets[i]] = emails[i];
      emailToReferral[emails[i]] = referrals[i];
      emit WalletLinked(keccak256(abi.encodePacked(emails[i])), wallets[i], referrals[i]);
      processPayment(wallets[i],emails[i]);
    }
  }

  function processPayment(address reciever, string memory email) private {
    address payable wallet = payable(reciever); // Changed to payable to allow transfer of ETH

    // Process Token Payments
    address[] memory tokens = emailTokens[email];
    for (uint256 i = 0; i < tokens.length; i++) {
      address tokenAddress = tokens[i];
      IERC20 tokenInstance = IERC20(tokenAddress);
      uint256 amount = emailDeposits[email][tokenAddress];
      if (amount > 0) {
        bool result = tokenInstance.transfer(wallet, amount);
        if(result) {
          emailDeposits[email][tokenAddress] = 0;
          emit PaymentProcessed(keccak256(abi.encodePacked(email)), wallet, tokenAddress, amount);
        }
      }
    }

    // Process ETH Payments
    uint256 ethAmount = emailDeposits[email][address(0)];
    if (ethAmount > 0) {
      bool result = wallet.send(ethAmount);
      if(result) {
        emailDeposits[email][address(0)] = 0;
        emit PaymentProcessed(keccak256(abi.encodePacked(email)), wallet, address(0), ethAmount); // Using address(0) as a placeholder for ETH
      }
    }
  }

  function multiSendDiffToken(
    string[] calldata emails,
    uint256[] calldata amounts,
    address token
  ) external nonReentrant {
    require(emails.length > 0, 'emails list is empty');
    require(emails.length == amounts.length, 'Lengths of emails and amounts arrays do not match');

    (uint256 taxes, uint256 totalSum) = calculateTotalAmountTaxes(amounts);

    uint256 totalAmount = totalSum.add(taxes);

    IERC20 tokenInstance = IERC20(token);

    require(totalAmount <= tokenInstance.balanceOf(msg.sender), 'Low balance');
    require(totalAmount <= tokenInstance.allowance(msg.sender, address(this)), 'Low allowance');

    for (uint256 i = 0; i < emails.length; i++) {
      require(amounts[i] > 0, 'Value must be more than 0');
      require(bytes(emails[i]).length > 0, 'Email is empty');
      if (emailToWallet[emails[i]] != address(0)) {
        tokenInstance.safeTransferFrom(msg.sender, emailToWallet[emails[i]], amounts[i]);
        if (emailToReferral[emails[i]] != address(0) && emailToReferral[emails[i]] != _msgSender())
          tokenInstance.safeTransferFrom(
            msg.sender,
            emailToReferral[emails[i]],
            (amounts[i].mul(referralPercent)).div(10000)
          );
      } else {
        tokenInstance.safeTransferFrom(msg.sender, address(this), amounts[i]);
        if (emailToReferral[emails[i]] != address(0) && emailToReferral[emails[i]] != _msgSender())
          tokenInstance.safeTransferFrom(
            msg.sender,
            emailToReferral[emails[i]],
            (amounts[i].mul(referralPercent)).div(10000)
          );
        emailDeposits[emails[i]][token] = emailDeposits[emails[i]][token].add(amounts[i]);
        emailTokens[emails[i]].push(token);
        emailDepositTimestamps[emails[i]][token] = block.timestamp;
        emit TokensSent(keccak256(abi.encodePacked(emails[i])), token, amounts[i]);
      }
    }

    tokenInstance.safeTransferFrom(msg.sender, bank, taxes);
  }

  function multiSendDiffETH(
    string[] calldata emails,
    uint256[] calldata amounts
  ) external payable nonReentrant {
    require(emails.length > 0, 'emails list is empty');
    require(emails.length == amounts.length, 'Lengths of emails and amounts arrays do not match');

    (uint256 taxes, uint256 totalSum) = calculateTotalAmountTaxes(amounts);

    uint256 totalAmount = totalSum.add(taxes);

    require(totalAmount <= msg.value, 'Sent ETH is less than the total amount required');

    for (uint256 i = 0; i < emails.length; i++) {
      require(amounts[i] > 0, 'Value must be more than 0');
      require(bytes(emails[i]).length > 0, 'Email is empty');
      if (emailToWallet[emails[i]] != address(0)) {
        payable(emailToWallet[emails[i]]).transfer(amounts[i]);
        if (emailToReferral[emails[i]] != address(0) && emailToReferral[emails[i]] != _msgSender())
          payable(emailToReferral[emails[i]]).transfer(
            (amounts[i].mul(referralPercent)).div(10000)
          );
      } else {
        emailDeposits[emails[i]][address(0)] = emailDeposits[emails[i]][address(0)].add(amounts[i]);
        emailDepositTimestamps[emails[i]][address(0)] = block.timestamp;
        emit TokensSent(keccak256(abi.encodePacked(emails[i])), address(0), amounts[i]);
      }
    }

    bank.transfer(taxes);
  }

  function reclaimUnclaimedTokens(
    string calldata email,
    address token
  ) external nonReentrant onlyModeratorAndOwner payable {
    require(emailToWallet[email] == address(0), 'Email is linked to a wallet');
    require(
      block.timestamp > emailDepositTimestamps[email][token].add(UNCLAIMED_DURATION),
      'Tokens are not yet reclaimable'
    );

    uint256 unclaimedAmount = emailDeposits[email][token];
    require(unclaimedAmount > 0, 'No unclaimed tokens for this email and token');

    
    bool result=IERC20(token).transfer(msg.sender, unclaimedAmount);
    if(result) {
      emit TokensReclaimed(keccak256(abi.encodePacked(email)), token, unclaimedAmount);
      emailDeposits[email][token] = 0;
    }
  }

  function reclaimUnclaimedETH(string calldata email) external nonReentrant onlyModeratorAndOwner {
    require(emailToWallet[email] == address(0), 'Email is linked to a wallet');
    require(
      block.timestamp > emailDepositTimestamps[email][address(0)].add(UNCLAIMED_DURATION),
      'ETH is not yet reclaimable'
    );

    uint256 unclaimedAmount = emailDeposits[email][address(0)];
    require(unclaimedAmount > 0, 'No unclaimed ETH for this email');

    bool result= payable(msg.sender).send(unclaimedAmount);
   
    if(result) {
      emailDeposits[email][address(0)] = 0;
      emit TokensReclaimed(keccak256(abi.encodePacked(email)), address(0), unclaimedAmount);
    }
  }

  function calculateTotalAmountTaxes(
    uint256[] calldata amounts
  ) public view returns (uint256 taxes, uint256 totalSum) {
    totalSum = 0;
    taxes = 0;
    uint256 arrayLength = amounts.length;
    for (uint256 i = 0; i < arrayLength; i++) {
      uint256 fee = (amounts[i].mul(percent)).div(10000);
      totalSum = totalSum.add(amounts[i]);
      taxes = taxes.add(fee);
    }
  }

  // Getter
  function emailByWallet(address wallet) public view onlyModeratorAndOwner returns (string memory) {
    return walletToEmail[wallet];
  }

  // Setter
  function emailByWallet(address wallet, string memory email) public onlyModeratorAndOwner {
    walletToEmail[wallet] = email;
  }

  // Getter
  function walletByEmail(string memory email) public view onlyModeratorAndOwner returns (address) {
    return emailToWallet[email];
  }

  // Setter
  function walletByEmail(string memory email, address wallet) public onlyModeratorAndOwner {
    emailToWallet[email] = wallet;
  }

  // Getter
  function referralByEmail(
    string memory email
  ) public view onlyModeratorAndOwner returns (address) {
    return emailToReferral[email];
  }

  // Setter
  function referralByEmail(string memory email, address referral) public onlyModeratorAndOwner {
    emailToReferral[email] = referral;
  }

  // Getter
  function depositByEmailAndAddress(
    string memory email,
    address addr
  ) public view onlyModeratorAndOwner returns (uint256) {
    return emailDeposits[email][addr];
  }

  // Setter
  function depositByEmailAndAddress(
    string memory email,
    address addr,
    uint256 amount
  ) public onlyModeratorAndOwner {
    emailDeposits[email][addr] = amount;
  }

  // Getter
  function tokensByEmail(
    string memory email
  ) public view onlyModeratorAndOwner returns (address[] memory) {
    return emailTokens[email];
  }

  // Setter
  function tokenByEmail(string memory email, address token) public onlyModeratorAndOwner {
    emailTokens[email].push(token);
  }

  // Getter
  function depositTimestampByEmailAndAddress(
    string memory email,
    address addr
  ) public view onlyModeratorAndOwner returns (uint256) {
    return emailDepositTimestamps[email][addr];
  }

  // Setter
  function depositTimestampByEmailAndAddress(
    string memory email,
    address addr,
    uint256 timestamp
  ) public onlyModeratorAndOwner {
    emailDepositTimestamps[email][addr] = timestamp;
  }
}
