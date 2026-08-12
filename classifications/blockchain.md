# Blockchain 攻防深度手册

## 1. 智能合约漏洞

### 1.1 常见漏洞类型

| 漏洞类型 | 描述 | 严重程度 |
|----------|------|----------|
| 重入攻击 | 函数在执行过程中被再次调用 | 🔴 严重 |
| 整数溢出 | 算术运算超出范围 | 🔴 严重 |
| 访问控制缺失 | 未验证调用者权限 | 🔴 严重 |
| 余额计算错误 | 余额扣减/增加逻辑错误 | 🔴 严重 |
| 随机数可预测 | 使用区块数据作随机数 | 🟡 中等 |
| 未检查返回值 | 外部调用返回值未检查 | 🟡 中等 |
| DoS 攻击 | 循环中调用外部合约 | 🟡 中等 |
| 闪电贷款攻击 | 利用闪电贷款放大攻击 | 🔴 严重 |
| 抢跑攻击 | 交易排序攻击 | 🟡 中等 |
| 合约升级攻击 | 代理模式恶意升级 | 🔴 严重 |
| 签名重用 | 相同参数签名重用 | 🟡 中等 |
| 价格操纵 | Oracle 价格操纵 | 🔴 严重 |
| 交易顺序依赖 | 改变交易顺序获利 | 🟡 中等 |

### 1.2 重入攻击详解

```solidity
// 漏洞合约示例
contract VulnerableBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // 漏洞: 先转账后更新状态
    function withdraw() public {
        require(balances[msg.sender] > 0);
        msg.sender.call{value: balances[msg.sender]}("");  // ← 先转账
        balances[msg.sender] = 0;  // ← 后更新
    }
}

// 攻击合约
contract Attack {
    VulnerableBank public bank;
    uint public attacherBalance;

    constructor(VulnerableBank _bank) {
        bank = _bank;
    }

    function attack() public payable {
        bank.deposit{value: msg.value}();
        bank.withdraw();
    }

    // 回退函数: 在 bank.withdraw() 转账时被调用
    fallback() external payable {
        if (address(bank).balance >= 1 ether) {
            bank.withdraw();  // 重入!
        }
    }
}

// 防御: Checks-Effects-Interactions 模式
function withdraw() public {
    uint balance = balances[msg.sender];
    require(balance > 0);
    balances[msg.sender] = 0;  // ← 先更新状态 (Effect)
    msg.sender.call{value: balance}("");  // ← 再外部调用 (Interaction)
}

// 防御: ReentrancyGuard
contract SafeBank is ReentrancyGuard {
    function withdraw() public nonReentrant {
        // 安全
    }
}

// 防御: Pull over Push
// 不要直接转账，而是让用户主动领取
mapping(address => uint) public pendingWithdrawals;

function withdraw() public {
    uint amount = pendingWithdrawals[msg.sender];
    require(amount > 0);
    pendingWithdrawals[msg.sender] = 0;
    // 调用者主动调用 claim
    msg.sender.transfer(amount);
}
```

### 1.3 整数溢出

```solidity
// 漏洞: 整数溢出 (Solidity 0.8 前)
function transfer(address to, uint amount) public {
    balances[msg.sender] -= amount;  // ← 下溢出: amount > balance
    balances[to] += amount;          // ← 上溢出
}

// 防御 (Solidity 0.8): 内置安全检查
// 0.8 前使用 SafeMath
using SafeMath for uint;
balances[msg.sender].sub(amount);
balances[to].add(amount);

// 漏洞示例: 绕过余额检查
function withdraw(uint amount) public {
    if (balances[msg.sender] >= amount) {  // uint, 无负数
        balances[msg.sender] -= amount;   // amount 很大时下溢出
        msg.sender.call{value: amount}("");
    }
}
// 攻击: 传入 amount > balance, 下溢出后余额变为 2^256 - amount + balance
```

### 1.4 访问控制

```solidity
// 漏洞: 缺失权限检查
function withdrawAll() public {  // 任何人都能调用
    msg.sender.call{value: address(this).balance}("");
}

// 防御
address public owner;
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

function withdrawAll() public onlyOwner {
    msg.sender.call{value: address(this).balance}("");
}

// 角色权限
mapping(address => Role) public roles;
modifier hasRole(Role role) {
    require(roles[msg.sender] == role);
    _;
}
```

### 1.5 随机数可预测

```solidity
// 漏洞: 使用区块数据作随机数
function random() public view returns (uint) {
    return block.timestamp + block.difficulty + uint(keccak256(msg.sender));
}
// 攻击者可在自己的链上计算相同值 → 提前知道结果

// 防御: Commit-Reveal 模式
// 1. 用户 commit 哈希 (hash(secret))
// 2. 揭示 secret
// 3. 验证 hash(secret) == committed hash
function commit(bytes32 hash) public {
    commits[msg.sender] = hash;
}
function reveal(uint secret) public {
    require(commits[msg.sender] == keccak256(abi.encode(secret)));
    // 使用 secret
}
```

### 1.6 闪电贷款攻击

```solidity
// 利用闪电贷款瞬时获取资金
// 攻击流程:
// 1. 在同一交易内借闪电贷款
// 2. 用贷款资金操纵价格/投票
// 3. 执行攻击
// 4. 还款 + 保留利润

// 示例: 操纵 DAO 投票
function flashLoanAttack() external {
    // 1. 借闪电贷款
    uint amount = 1000 ether;
    ICreamVault(address(this)).flashLoan(amount);
    
    // 2. 用资金投票
    dao.vote(amount);  // 大量代币投票
    
    // 3. 执行恶意操作
    dao.executeProposal(maliciousProposal);
    
    // 4. 还款
    repay(amount);
}
```

---

## 2. 重放攻击

```solidity
// 漏洞: 签名可重用
function transferWithSignature(address from, address to, uint amount, bytes signature) public {
    bytes32 hash = keccak256(abi.encode(from, to, amount));
    require(recoverSigner(hash, signature) == from);
    // 同一签名可被多次使用!
}

// 防御: Nonce + 签名
mapping(address => uint) public nonces;
mapping(bytes32 => bool) public usedSignatures;

function transferWithSignature(address from, address to, uint amount, uint nonce, bytes signature) public {
    bytes32 hash = keccak256(abi.encode(from, to, amount, nonce));
    require(!usedSignatures[hash], "Signature already used");
    require(nonce == nonces[from], "Invalid nonce");
    address signer = recoverSigner(hash, signature);
    require(signer == from, "Invalid signature");
    
    usedSignatures[hash] = true;
    nonces[from]++;
    // 执行转账
}
```

---

## 3. 智能合约审计清单

| 检查项 | 说明 | 工具 |
|--------|------|------|
| 重入攻击 | Checks-Effects-Interactions | Slither, Mythril |
| 整数溢出 | SafeMath / Solidity 0.8 | Slither |
| 权限控制 | onlyOwner / Role 检查 | Mythril |
| 随机数 | Commit-Reveal 模式 | 手动审计 |
| 闪电贷款 | 价格操纵防护 | 手动审计 |
| 未检查返回值 | 检查 call/transfer 返回值 | Slither |
| DoS | 避免循环外部调用 | Slither |
| Oracle 操纵 | 价格操纵防护 | Chainlink, TWAP |
| 合约升级 | 透明代理 + 时间锁 | OpenZeppelin |
| 签名重用 | Nonce + 签名记录 | 手动审计 |
| 抢跑攻击 | Commit-Reveal | 手动审计 |
| 交易顺序 | 合理时间戳 | 手动审计 |

### 审计工具

```bash
# Slither - 静态分析
slither . --detect reentrancy,integer-overflow,unused-variable

# Mythril - 符号执行
myth -ksc contract.sol

# Manticore - 符号执行
manticore contract.sol

# Echidna - 模糊测试
echidna-test . --contract ContractName

# Foundry - 单元测试 + 模糊
forge test
forge invariant

# Hardhat - 测试
npx hardhat test
```

---

## 4. 常用命令

```bash
# 部署合约
# Remix IDE
# Hardhat: npx hardhat run scripts/deploy.js --network mainnet
# Foundry: forge create ContractName --rpc-url $RPC_URL

# 验证合约
# Etherscan: npx hardhat verify $CONTRACT_ADDRESS ...

# 查看合约
# cast: cast call $CONTRACT_ADDRESS "functionName(uint)" $ARG
# cast: cast send $CONTRACT_ADDRESS "functionName(address)" $ARG

# 测试
# forge test -vvvv
# npx hardhat test

# 部署到测试网
# Goerli: forge create Contract --rpc-url https://goerli.infura.io/v3/$KEY
# 本地: anvil → forge create
```