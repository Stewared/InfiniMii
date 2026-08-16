import test from "node:test";
import assert from "node:assert/strict";

import {
  MII_LIST_SORT_DIRECTION_VALUES,
  MII_LIST_SORT_VALUES,
  getDefaultMiiListSortDirection,
  getMiiListSortStages,
  normalizeMiiListSort,
  normalizeMiiListSortDirection,
  normalizeMiiSearchSort,
  sortMiiListItems,
} from "../miiListSort.js";
import {
  getMiiSearchSort,
  sortRankedMiiSearchCandidates,
} from "../searchUtils.js";

test("public Mii list sort values and legacy aliases are normalized", () => {
  assert.deepEqual(MII_LIST_SORT_VALUES, [
    "alphabetical",
    "trending",
    "top",
    "latest",
  ]);
  assert.equal(normalizeMiiListSort(" Alphabetical "), "alphabetical");
  assert.equal(normalizeMiiListSort("popular"), "top");
  assert.equal(normalizeMiiListSort("recent"), "latest");
  assert.equal(normalizeMiiListSort("not-a-sort"), "top");
  assert.equal(normalizeMiiListSort(["latest"]), "top");
  assert.equal(normalizeMiiSearchSort(undefined, true), "relevance");
  assert.equal(normalizeMiiSearchSort("relevance", true), "relevance");
  assert.equal(normalizeMiiSearchSort("relevance", false), "top");
  assert.equal(normalizeMiiSearchSort("latest", true), "latest");
});

test("sort directions are normalized without changing each sort's existing default", () => {
  assert.deepEqual(MII_LIST_SORT_DIRECTION_VALUES, ["asc", "desc"]);
  assert.equal(getDefaultMiiListSortDirection("alphabetical"), "asc");
  assert.equal(getDefaultMiiListSortDirection("trending"), "desc");
  assert.equal(getDefaultMiiListSortDirection("top"), "desc");
  assert.equal(getDefaultMiiListSortDirection("latest"), "desc");
  assert.equal(getDefaultMiiListSortDirection("relevance"), "desc");
  assert.equal(normalizeMiiListSortDirection(undefined, "alphabetical"), "asc");
  assert.equal(normalizeMiiListSortDirection(undefined, "latest"), "desc");
  assert.equal(normalizeMiiListSortDirection(" ASCENDING ", "top"), "asc");
  assert.equal(
    normalizeMiiListSortDirection("descending", "alphabetical"),
    "desc"
  );
  assert.equal(
    normalizeMiiListSortDirection("sideways", "alphabetical"),
    "asc"
  );
});

test("alphabetical stages use the displayed Mii name and a stable tie break", () => {
  const stages = getMiiListSortStages("alphabetical", 123);
  assert.equal(
    stages[0].$addFields.listSortName.$toLower.$let.vars.metaName.$trim.input
      .$ifNull[0],
    "$meta.name"
  );
  assert.deepEqual(stages[1], {
    $sort: { listSortName: 1, uploadedOn: -1, _id: -1 },
  });

  const descendingStages = getMiiListSortStages("alphabetical", "desc");
  assert.deepEqual(descendingStages[1], {
    $sort: { listSortName: -1, uploadedOn: -1, _id: -1 },
  });
  assert.deepEqual(getMiiListSortStages("top", "asc"), [
    { $sort: { votes: 1, uploadedOn: -1, _id: -1 } },
  ]);
  assert.deepEqual(getMiiListSortStages("latest", "asc"), [
    { $sort: { uploadedOn: 1, _id: -1 } },
  ]);
});

test("relevance direction flips only score and keeps stable tie breakers", () => {
  assert.deepEqual(getMiiSearchSort("desc"), {
    searchScore: -1,
    votes: -1,
    uploadedOn: -1,
    _id: -1,
  });
  assert.deepEqual(getMiiSearchSort("asc"), {
    searchScore: 1,
    votes: -1,
    uploadedOn: -1,
    _id: -1,
  });

  const candidates = [
    { id: "best", searchScore: 200, votes: 4, uploadedOn: 10 },
    { id: "low-liked", searchScore: 50, votes: 2, uploadedOn: 30 },
    { id: "low-popular", searchScore: 50, votes: 20, uploadedOn: 20 },
  ];

  assert.deepEqual(
    sortRankedMiiSearchCandidates(candidates, "desc").map((item) => item.id),
    ["best", "low-popular", "low-liked"]
  );
  assert.deepEqual(
    sortRankedMiiSearchCandidates(candidates, "asc").map((item) => item.id),
    ["low-popular", "low-liked", "best"]
  );
});

test("list item sorting supports alphabetical, top, latest, and trending", () => {
  const now = Date.UTC(2026, 0, 10);
  const day = 24 * 60 * 60 * 1000;
  const items = [
    {
      id: "a",
      meta: { name: "Zelda" },
      votes: 100,
      uploadedOn: now - 30 * day,
    },
    { id: "b", meta: { name: "amy" }, votes: 10, uploadedOn: now - day },
    { id: "c", meta: { name: "Amy 2" }, votes: 20, uploadedOn: now - 2 * day },
  ];

  assert.deepEqual(
    sortMiiListItems(items, "alphabetical", now).map((item) => item.id),
    ["b", "c", "a"]
  );
  assert.deepEqual(
    sortMiiListItems(items, "top", now).map((item) => item.id),
    ["a", "c", "b"]
  );
  assert.deepEqual(
    sortMiiListItems(items, "latest", now).map((item) => item.id),
    ["b", "c", "a"]
  );
  assert.deepEqual(
    sortMiiListItems(items, "trending", now).map((item) => item.id),
    ["b", "c", "a"]
  );

  assert.deepEqual(
    sortMiiListItems(items, "alphabetical", "desc").map((item) => item.id),
    ["a", "c", "b"]
  );
  assert.deepEqual(
    sortMiiListItems(items, "top", "asc").map((item) => item.id),
    ["b", "c", "a"]
  );
  assert.deepEqual(
    sortMiiListItems(items, "latest", "asc").map((item) => item.id),
    ["a", "c", "b"]
  );
  assert.deepEqual(
    sortMiiListItems(items, "trending", now, "asc").map((item) => item.id),
    ["a", "c", "b"]
  );
});
