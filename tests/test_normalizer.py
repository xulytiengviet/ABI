"""Regression tests for packed slots, nested mappings, no hallucinated types.

These test normalizer logic on synthetic *Datalog relation fixtures* only.
They do not certify full Gigahorse execution.
"""
import unittest

from backend.normalizer import normalize, _root, _packed


class NormalizeTests(unittest.TestCase):
    def test_slot_shared_without_collision(self):
        r = normalize({
            "StorageVariableInfo": [
                ["stor0x0_0_19","$Storage()","0x0","0","19"],
                ["stor0x0_20_20","$Storage()","0x0","20","20"],
                ["stor0x0_21_31","$Storage()","0x0","21","31"],
            ],
            "StorageVariable_Type": [
                ["$Storage()","$TightlyPackedVariable($Constant(0x0), 0, 19)","address"],
                ["$Storage()","$TightlyPackedVariable($Constant(0x0), 20, 20)","bool"],
                ["$Storage()","$TightlyPackedVariable($Constant(0x0), 21, 31)","uint88"],
            ],
        }, 33)
        self.assertEqual(len(r["slots"]),1)
        slot = r["slots"][0]
        self.assertEqual(slot["slot"],"0x0")
        self.assertFalse(slot["overlapObserved"])
        self.assertEqual([(x["offset"],x["width"]) for x in slot["fields"]],[(0,20),(20,1),(21,11)])
        self.assertEqual([x["type"] for x in slot["fields"]],["address","bool","uint88"])

    def test_overlap_not_automatically_collision(self):
        r=normalize({"StorageVariableInfo":[
            ["A","$Storage()","0x0","0","20"],
            ["B","$Storage()","0x0","19","31"],
        ]},24)
        self.assertTrue(r["slots"][0]["overlapObserved"])
        self.assertIn("chưa đủ cơ sở kết luận",r["warnings"][0])

    def test_nested_mapping_types(self):
        r=normalize({
            "Mapping_KeyType":[
                ["$Storage()","$Mapping($Constant(0x4))","address"],
                ["$Storage()","$Mapping($Mapping($Constant(0x4)))","uint256"],
            ],
            "DataStructure_ValueOrElementType":[
                ["$Storage()","$Mapping($Mapping($Constant(0x4)))","uint128"],
            ],
            "StorageStmtKindAndConstruct":[
                ["stmt1","$VariableAccess()","$Storage()","$Variable($Mapping($Mapping($Constant(0x4))))"]
            ],
        },151)
        deepest=next(x for x in r["mappings"] if x["depth"]==2)
        self.assertEqual(deepest["slot"],"0x4")
        self.assertEqual([x["type"] for x in deepest["keys"]],["address","uint256"])
        self.assertEqual(deepest["valueType"],"uint128")
        self.assertTrue(deepest["evidence"])

    def test_no_invented_key_and_value(self):
        r=normalize({"StorageStmtKindAndConstruct":[
            ["stmt2","$VariableAccess()","$Storage()","$Mapping($Constant(0x9))"],
        ]}, 45)
        m=r["mappings"][0]
        self.assertEqual(m["keys"],[{"type":"unknown"}])
        self.assertEqual(m["valueType"],"unknown")

    def test_parser(self):
        self.assertEqual(_root("$Variable($Mapping($Constant(0x0004)))"),"0x4")
        self.assertEqual(_packed("$TightlyPackedVariable($Constant(0x0), 0, 19)"),(0,19))
        self.assertIsNone(_packed("$TightlyPackedVariable($Constant(0x0), 0, 80)"))


if __name__=="__main__":
    unittest.main()
