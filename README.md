# ABI NEXUS — EVM Reverse Engineering & MEV Intelligence

Giao diện Web3 neon, 100% tiếng Việt, triển khai tĩnh trên GitHub Pages cho phân tích hợp đồng thông minh Ethereum.

## Tính năng đã có

- **ABI Decoder:** nhập/tải JSON ABI hoặc Etherscan API result; phân tích function, event, error, 4-byte selectors và event topic; xuất báo cáo JSON, tái dựng **Solidity interface** từ ABI.
- **Transaction Lab:** giải mã calldata bằng ethers.js v6; tra cứu transaction/receipt trên Ethereum JSON-RPC chỉ đọc; giải mã logs bằng ABI người dùng cung cấp; hiển thị gas và phí giao dịch.
- **Bytecode Explorer:** disassembler EVM chạy trực tiếp trong trình duyệt, hiểu PUSH0 và một số opcode mới; thống kê SLOAD/SSTORE, calls, function selector **ứng viên**, constants gần thao tác storage (chỉ là heuristic). Tra runtime code và đọc slot proxy ERC-1967.
- **MEV Intelligence:** ghi nhận chứng cứ RPC của một transaction và (nếu endpoint hỗ trợ) các giao dịch lân cận trong block. **Không xác nhận MEV** khi chưa có execution traces, token flow và lợi nhuận thực.

## ABI NEXUS v2 — Storage Layout + Mapping Recovery

Bản này đã bổ sung hai tab chuyên sâu ngay trên giao diện GitHub Pages:

- **Storage Layout Explorer (#storage):** đọc runtime bytecode, quét cục bộ có nhãn heuristic, biểu diễn từng slot 32 byte và các khoảng đã suy ra từ SHR/AND; hiển thị số lượng storage/mapping và chứng cứ. Nút "Lấy từ Bytecode Explorer" sử dụng dữ liệu trong tab trước.
- **Mapping Type Recovery (#mapping):** phát hiện đường truy cập KECCAK256 khi luồng stack tuyến tính đủ chứng cứ, thể hiện mapping nhiều cấp, hoặc nhận Mapping_KeyType và DataStructure_ValueOrElementType từ backend DYELS; ABI getter được trình bày riêng như dấu hiệu hỗ trợ, không tự xác nhận một mapping.
- **FastAPI Gigahorse–DYELS connector:** có source ở [backend/](backend/README.md), một client Datalog thật để xuất các relation, chuẩn hóa JSON IR cho byte offset / width / nested mapping. Giới hạn runtime, serialize các yêu cầu, kiểm tra đầu vào.
- **Kiểm thử tự động:** bộ regression tests cho packed variables có cùng slot, nested mapping, overlap và unknown type.

**Ranh giới triển khai:** hai tab và quét cục bộ được xuất bản lên GitHub Pages; **backend DYELS không chạy trên GitHub Pages và hiện không có endpoint DYELS được triển khai trong repository**. Muốn sử dụng phân tích Datalog thật phải cài Gigahorse, Soufflé và FastAPI trên máy chủ riêng, nhập HTTPS backend URL trong tab Storage Explorer. Nếu backend chưa cài, nút DYELS sẽ báo lỗi rõ ràng, không tạo kết quả giả.

Mở trực tiếp:
- https://xulytiengviet.github.io/ABI/#storage
- https://xulytiengviet.github.io/ABI/#mapping

**Về an toàn:** Việc dùng phân tích cục bộ không tải dữ liệu lên backend. Bấm "Chạy phục hồi DYELS" sẽ gửi bytecode đến backend URL do người dùng cung cấp. Backend phải được chạy trong môi trường cô lập với quyền truy cập hạn chế và cấu hình CORS/kiểm soát tải, không phơi máy chủ phân tích công khai thiếu rate limiting.

## Mức độ phục hồi

ABI là mô tả giao diện công khai của hợp đồng, không chứa đầy đủ trạng thái, function private hay source code gốc. Đầu ra Solidity trong giao diện là *interface reconstructed from ABI*, **không phải hợp đồng được giải mã hoàn chỉnh**.

Bytecode Explorer là trình disassemble + tập heuristic đơn giản. **Không giả vờ chạy VarLifter**. Lõi VarLifter gốc là Python static analysis cần triển khai trong một dịch vụ backend sandbox riêng. Nếu muốn phục hồi state variables/types thật, bổ sung một API backend phiên bản đã được nâng cấp và kiểm thử, với giấy phép VarLifter được xác minh độc lập.

Trình phân tích MEV không thể xác định sandwich / arbitrage chỉ từ selector, ABI, calldata hoặc một giao dịch riêng lẻ.

## Chạy thử

Mở index.html qua local web server, ví dụ:

    python -m http.server 8000

Truy cập http://localhost:8000. Cần mạng để tải thư viện ethers.js và Google Fonts. Có thể thay CDN bằng bản vendored được kiểm tra checksum để chạy offline hoàn toàn.

Trên GitHub Pages, vào Settings > Pages, chọn **GitHub Actions** và workflow "Deploy ABI Nexus to GitHub Pages". URL dự kiến (chỉ hoạt động sau khi Pages được kích hoạt):

https://xulytiengviet.github.io/ABI/

## Sử dụng

1. Chọn "Giải mã ABI", nhập ABI JSON hoặc nhấn "Dùng mẫu ERC-20" và "Phân tích ABI".
2. Mở "Giao dịch ETH", nhập calldata rồi giải mã, hoặc nhập transaction hash và Ethereum HTTPS RPC để tải thông tin từ chain.
3. Mở "Phục hồi Bytecode", nhập runtime bytecode hoặc contract address, kiểm tra số opcode, selector ứng viên, storage read/write và ERC-1967.
4. Mở "MEV Intelligence" để phân tích chứng cứ quan sát. Kết luận mặc định **INCONCLUSIVE** khi không đủ dữ liệu.

## Cấu trúc

- index.html — khung giao diện và nội dung tiếng Việt.
- styles.css — Web3 neon UI responsive.
- app.js — ABI / transaction / RPC / EVM disassembly / MEV evidence logic.
- .github/workflows/pages.yml — workflow deploy Pages nếu được cấp quyền.

## Quyền riêng tư và an toàn

- Không nhận và không lưu seed phrase, private key; không có chức năng ký hoặc gửi giao dịch.
- ABI, bytecode và calldata được xử lý trong trình duyệt.
- Khi dùng RPC, trình duyệt gửi truy vấn và IP đến nhà cung cấp endpoint; hãy chọn nhà cung cấp đáng tin cậy.
- Kết quả phân tích không thay thế security audit chuyên sâu.
- Không tự gửi dữ liệu đến một analytics backend.
- Chỉ kết nối Ethereum JSON-RPC HTTPS hoặc localhost trong trường hợp thử nghiệm.

## Tham khảo

- VarLifter OOPSLA 2024: https://doi.org/10.1145/3689711
- Zenodo VarLifter: https://zenodo.org/records/12670354
- Solidity ABI Specification: https://docs.soliditylang.org/en/latest/abi-spec.html
- ERC-1967 Proxy Slots: https://eips.ethereum.org/EIPS/eip-1967
- Ethereum JSON-RPC: https://ethereum.org/en/developers/docs/apis/json-rpc/

**Lưu ý bản quyền:** Không nhúng hoặc cấp phép lại toàn bộ mã nguồn VarLifter trong dự án này khi chưa xác minh giấy phép phần mềm tương ứng.
